#!/usr/bin/env python3
"""The third-party counterparty for level 2 interoperability (design doc section 8).

# Why this file is Python and not Rust

Level 1 (`tests/two_parties.rs`) drives a second `matrix_sdk_crypto::OlmMachine`
directly, so both parties run the same protocol state machine this library
holds. A consistent misreading of the Matrix E2EE spec passes that test
cleanly. `matrix-nio` implements its own Olm/Megolm session lifecycle, device
tracking and key-sharing decisions in Python, so it has to agree with us on
the wire without sharing the code that produces either side of it.

The independence is at the protocol level, not all the way down: nio 0.26.0
moved its ratchet from libolm to `vodozemac`, which is the same crate
`matrix-sdk-crypto` uses (`rust/Cargo.lock`: vodozemac 0.10.0). A defect
inside `vodozemac` itself would pass both sides. Everything above it -- event
shapes, `/keys/*` payloads, to-device routing, the megolm event body -- is two
independent implementations agreeing or not.

# Protocol

Newline-delimited JSON on stdin, one JSON reply per line on stdout. The Rust
test owns the sequencing; this process only does what it is told, so a failure
is attributable to a step rather than to a race between two long-running
clients.

Nothing is ever printed outside that protocol, and nothing is written to disk
except nio's own crypto store, in a temporary directory the caller supplies
and removes.

# The level 2 proofs, one counterparty

This process serves every level 2 test that takes a matrix-nio counterparty.
`level_two_interop.rs` uses the encryption operations (`send`, `collect`);
`level_two_verification.rs` uses the `sas_*` ones; `level_two_identity.rs`
uses `identity_probe` alongside `send`. `level_two_federated.rs` uses `join`
and `history` alongside the encryption ones, for the second account it runs
as, on a second homeserver. They share the login, the sync pump and the
store, which is the whole reason they share a file: a second script would be
a second, slightly different idea of what "settle" means.

# Credentials

The password arrives in the environment (`MATRIX_INTEROP_PASSWORD`) and is
read once, into a local, at login. It is never written to a file, never echoed
into a reply, and never placed on a command line, where `ps` would show it.
"""

import asyncio
import base64
import hashlib
import json
import os
import sys
import traceback

from nio import (
    Api,
    AsyncClient,
    AsyncClientConfig,
    JoinResponse,
    LoginResponse,
    MegolmEvent,
    RoomMessagesResponse,
    RoomSendResponse,
    ToDeviceResponse,
)
from nio.api import MessageDirection

# nio marks every device it has not verified as unverified, and refuses by
# default to send a room key to one. M2 verifies nothing on either side -- our
# own outbound half is `CollectStrategy::AllDevices` for the same reason (spec
# section 7.2) -- so the counterparty is held to the same standard rather than
# a stricter one it would fail on. This is the nio-side mirror of that
# decision, named here rather than passed silently at the call site.
IGNORE_UNVERIFIED = True


class Party:
    def __init__(self):
        self.client = None
        # The `m.key.verification.start` content of every comparison this
        # process opened, kept from the moment it was built. nio refuses to
        # rebuild one from a cancelled comparison, and a cancelled
        # comparison is exactly when `sas_commitment_probe` needs it.
        self.starts = {}
        # The newest `prev_batch` token per joined room, recorded off every
        # sync response by `_record_rooms`. `room_messages(start=...)` is
        # documented to accept a room timeline's prev_batch (or a prior
        # /messages token); the sync cursor `next_batch` is NOT on that
        # list, and passing it relies on homeserver-specific token
        # interchangeability -- a server is free to answer it with an
        # invalid-pagination-token error, which is what a late joiner's
        # history fetch then fails on.
        self.prev_batches = {}

    def _record_rooms(self, response):
        """Keep each joined room's timeline prev_batch from one sync response."""
        rooms = getattr(response, "rooms", None)
        if rooms is None:
            return
        for room_id, info in rooms.join.items():
            prev_batch = info.timeline.prev_batch
            if prev_batch is not None:
                self.prev_batches[room_id] = prev_batch

    async def op_login(self, cmd):
        homeserver = os.environ["MATRIX_INTEROP_HOMESERVER"]
        user_id = os.environ["MATRIX_INTEROP_USER"]
        store_path = os.environ["MATRIX_INTEROP_NIO_STORE"]
        password = os.environ["MATRIX_INTEROP_PASSWORD"]

        self.client = AsyncClient(
            homeserver,
            user_id,
            store_path=store_path,
            config=AsyncClientConfig(
                encryption_enabled=True,
                store_sync_tokens=False,
                request_timeout=60,
                max_timeouts=3,
            ),
        )
        response = await self.client.login(
            password, device_name="level-two-interop-nio"
        )
        del password
        if not isinstance(response, LoginResponse):
            return {"ok": False, "error": f"login failed: {response}"}

        await self.settle(rounds=3)
        return {
            "ok": True,
            "user_id": self.client.user_id,
            "device_id": self.client.device_id,
        }

    async def settle(self, rounds=3, timeout_ms=1000):
        """One turn of nio's own key pump: sync, publish keys, query devices.

        `AsyncClient.sync_forever` does this internally; a bare `sync` does
        not, and this test drives every step explicitly so an unpublished key
        is a visible missing step rather than a silent absence.
        """
        for _ in range(rounds):
            response = await self.client.sync(timeout=timeout_ms, full_state=False)
            self._record_rooms(response)
            if self.client.should_upload_keys:
                await self.client.keys_upload()
            if self.client.should_query_keys:
                await self.client.keys_query()

    async def op_settle(self, cmd):
        await self.settle(rounds=int(cmd.get("rounds", 3)))
        return {"ok": True}

    async def op_join(self, cmd):
        """Join a room by id, over federation if nio's own homeserver is not
        the room's origin. Used by `level_two_federated.rs`, which invites
        this process's user into a room that lives on the other server.

        The join only returns once the whole federation round trip has
        completed (make_join/send_join), so a successful reply means both
        servers already agree this user is a member.

        Why this re-implements AsyncClient.join instead of calling it: the
        pinned matrix-nio 0.26.0's `Api.join` sends the POST with NO body,
        which Synapse accepts and Continuwuity refuses -- its request
        deserializer demands JSON, and the refusal reads "M_BAD_JSON
        deserialization failed: EOF while parsing a value at line 1 column
        0". `AsyncClient.join` is exactly `_send(JoinResponse, method,
        path)` with no data, so calling `_send` with an explicit empty
        object is the same code path with the one byte Continuwuity needs
        added; it stays nio's own machinery, so JoinResponse parsing and
        the client's bookkeeping remain upstream's. If a future nio sends
        a body from Api.join, drop this and call client.join again.
        """
        path = f"/_matrix/client/v3/join/{cmd['room_id']}"
        response = await self.client._send(
            JoinResponse, "POST", path, data="{}", content_type="application/json"
        )
        if not isinstance(response, JoinResponse):
            return {"ok": False, "error": f"join failed: {response}"}
        return {"ok": True, "room_id": response.room_id}

    async def op_history(self, cmd):
        """Backfill room history before the current sync cursor, and report
        what nio makes of each event it fetches.

        Used by `level_two_federated.rs` for the late joiner's history. A
        /sync only ever moves forward: the pre-join events a freshly joined
        client is handed in its first syncs are consumed by those syncs and
        are not offered to a later `collect`. This op is what a real product
        does on opening a room -- paginate backwards from where it has
        synced to -- so the question "what can the late joiner make of the
        pre-join history" is answered by nio's own decrypt attempt on the
        fetched events, not by whichever events a previous sync happened
        to carry. It may backfill across federation from the room's origin
        server, which for this test is the entire point.

        `until_found` names event ids the caller needs in the result:
        pages keep being fetched (from the `end` token each page returns,
        going backwards) until every one of them has been seen or
        `max_rounds` pages have been read. One page is not enough on its
        own: the two implementations page differently (Synapse reached the
        pre-join message in a single page of 20 in the runs this test pins;
        Continuwuity returned only the two newest events), and an op whose
        answer depends on which side paginated how would be asserting the
        pager, not the cryptography.
        """
        room_id = cmd["room_id"]
        limit = int(cmd.get("limit", 20))
        until_found = set(cmd.get("until_found", []))
        max_rounds = int(cmd.get("max_rounds", 10))
        # The room's own prev_batch, recorded off the syncs `settle` ran
        # after the join -- the one token nio documents for starting
        # pagination. When no sync carried this room (this op is only ever
        # called after a settle, so that would already be a broken driver),
        # start is None and nio omits `from` from the request entirely: the
        # server answers with its current tail and the pages below still
        # walk backwards from there. What is not passed is the sync cursor
        # `next_batch`: pagination tokens and sync tokens are not
        # interchangeable per the spec, and a server may reject one where it
        # expects the other.
        start = self.prev_batches.get(room_id)
        events = {}

        def record(event):
            event_id = getattr(event, "event_id", None)
            if event_id is None:
                return
            if isinstance(event, MegolmEvent):
                try:
                    decrypted = self.client.decrypt_event(event)
                    events[event_id] = {
                        "decrypted": True,
                        "type": type(decrypted).__name__,
                        "body": getattr(decrypted, "body", None),
                    }
                except Exception as error:  # noqa: BLE001 -- reported, not handled
                    events[event_id] = {
                        "decrypted": False,
                        "type": "MegolmEvent",
                        "reason": f"{type(error).__name__}: {error}",
                    }
            else:
                events[event_id] = {
                    "decrypted": True,
                    "type": type(event).__name__,
                    "body": getattr(event, "body", None),
                }

        for _ in range(max_rounds):
            response = await self.client.room_messages(
                room_id,
                start=start,
                direction=MessageDirection.back,
                limit=limit,
            )
            if not isinstance(response, RoomMessagesResponse):
                return {"ok": False, "error": f"history fetch failed: {response}"}
            for event in response.chunk:
                record(event)
            found = until_found - set(events)
            if not found or not response.end or response.end == response.start:
                break
            start = response.end

        return {"ok": True, "events": events}

    async def op_send(self, cmd):
        """nio encrypts and sends. Direction 2 of the proof."""
        response = await self.client.room_send(
            cmd["room_id"],
            "m.room.message",
            {"msgtype": "m.text", "body": cmd["body"]},
            ignore_unverified_devices=IGNORE_UNVERIFIED,
        )
        if not isinstance(response, RoomSendResponse):
            return {"ok": False, "error": f"send failed: {response}"}
        return {"ok": True, "event_id": response.event_id}

    async def op_collect(self, cmd):
        """Sync until the named events have arrived, and report what nio made of each.

        `event_ids` is everything to observe; `require_decrypted` is the
        subset that must actually decrypt before this returns early. Both are
        needed in one call because a sync token only advances forwards: an
        event consumed by one `collect` is not offered to the next, so the
        deliberately corrupted control event has to be watched in the same
        call as the intact one it is the control for.

        An event that is still a `MegolmEvent` after the sync that carried it
        is retried on every later round, because the room key can arrive in a
        later sync than the message it unlocks. So "not decrypted" here means
        nio kept failing for the whole window with the key already in hand --
        which is what the corrupted control must produce, and what an intact
        event must not.
        """
        room_id = cmd["room_id"]
        wanted = set(cmd["event_ids"])
        must_decrypt = set(cmd.get("require_decrypted", []))
        deadline = asyncio.get_event_loop().time() + float(cmd.get("timeout_s", 90))

        done = {}
        pending = {}
        reasons = {}

        def outstanding():
            return (wanted - set(done) - set(pending)) or (must_decrypt - set(done))

        while outstanding() and asyncio.get_event_loop().time() < deadline:
            response = await self.client.sync(timeout=3000, full_state=False)
            self._record_rooms(response)
            rooms = getattr(response, "rooms", None)
            if rooms is not None and room_id in rooms.join:
                for event in rooms.join[room_id].timeline.events:
                    event_id = getattr(event, "event_id", None)
                    if event_id is None or event_id not in wanted or event_id in done:
                        continue
                    if isinstance(event, MegolmEvent):
                        pending[event_id] = event
                    else:
                        done[event_id] = {
                            "decrypted": True,
                            "type": type(event).__name__,
                            "body": getattr(event, "body", None),
                            "retried": False,
                        }

            for event_id, event in list(pending.items()):
                try:
                    decrypted = self.client.decrypt_event(event)
                    done[event_id] = {
                        "decrypted": True,
                        "type": type(decrypted).__name__,
                        "body": getattr(decrypted, "body", None),
                        "retried": True,
                    }
                    pending.pop(event_id)
                except Exception as error:  # noqa: BLE001 -- reported, not handled
                    reasons[event_id] = f"{type(error).__name__}: {error}"

        for event_id in pending:
            done[event_id] = {
                "decrypted": False,
                "type": "MegolmEvent",
                "reason": reasons.get(event_id, "never attempted"),
            }

        return {
            "ok": True,
            "events": done,
            "missing": sorted(wanted - set(done)),
        }

    # ------------------------------------------------------------------
    # Device verification by short authentication string
    #
    # nio speaks exactly one of the two shapes the Matrix protocol carries
    # for this: the deprecated bare `m.key.verification.start`, to-device
    # only, with `accept`, `key`, `mac` and `cancel` after it. Its event
    # vocabulary has no `request`, no `ready` and no `done` -- an
    # `m.key.verification.request` reaches it as an unrecognised to-device
    # event and is dropped -- and it has no in-room verification at all.
    #
    # So **nio always opens the flow** in the operations below. That is not
    # a preference of this harness; it is the only direction the two
    # implementations have in common, and the reason the Rust side of this
    # test drives it that way.
    #
    # Nothing here decides anything on nio's behalf either. No operation
    # below tells nio to cancel, and none is needed: it stops on its own,
    # at its own commitment check, and `sas_commitment_probe` exists to
    # attribute that stop rather than to cause it.
    # ------------------------------------------------------------------

    def _sas(self, transaction_id):
        sas = self.client.key_verifications.get(transaction_id)
        if sas is None:
            raise KeyError(
                f"nio is not taking part in a verification with transaction id "
                f"{transaction_id!r}; it knows "
                f"{sorted(self.client.key_verifications)}"
            )
        return sas

    def _sas_report(self, sas):
        """Everything nio knows about one comparison, in one shape.

        `decimals` and `emoji` are `None` until the keys have crossed --
        absent rather than empty, so the Rust side cannot mistake "not yet"
        for "there is nothing to show".
        """
        showable = sas.established_sas is not None
        device = sas.other_olm_device
        return {
            "state": sas.state.name,
            "verified": sas.verified,
            "canceled": sas.canceled,
            "sas_accepted": sas.sas_accepted,
            "we_started_it": sas.we_started_it,
            "cancel_code": sas.cancel_code,
            "decimals": list(sas.get_decimals()) if showable else None,
            "emoji": [list(pair) for pair in sas.get_emoji()] if showable else None,
            "verified_devices": list(sas.verified_devices),
            # Read back off the device store rather than off the comparison,
            # which is the same question the Rust side asks its own library
            # through `deviceStatuses`.
            "other_device_verified": self.client.device_store[device.user_id][
                device.id
            ].verified,
        }

    async def op_sas_start(self, cmd):
        """Open a comparison against the named device.

        The device has to be in nio's own store first, and that is the one
        precondition this whole exchange has: an `m.key.verification.start`
        naming a device nio has never queried is dropped on arrival with a
        log line and nothing else, and the same is true in reverse -- nio
        cannot address a device it has not been told about. So this settles
        until the device appears rather than assuming a previous `settle`
        was enough, and reports how many rounds that took.
        """
        user_id = cmd["user_id"]
        device_id = cmd["device_id"]
        deadline = asyncio.get_event_loop().time() + float(cmd.get("timeout_s", 60))

        rounds = 0
        device = None
        while device is None:
            try:
                device = self.client.device_store[user_id][device_id]
            except KeyError:
                if asyncio.get_event_loop().time() >= deadline:
                    return {
                        "ok": False,
                        "error": (
                            f"nio never learned about {user_id}'s device {device_id} "
                            f"after {rounds} query rounds, so it cannot address a "
                            f"verification to it"
                        ),
                    }
                rounds += 1
                await self.settle(rounds=1)

        message = self.client.create_key_verification(device)
        transaction_id = message.content["transaction_id"]
        self.starts[transaction_id] = dict(message.content)
        response = await self.client.to_device(message)
        if not isinstance(response, ToDeviceResponse):
            return {"ok": False, "error": f"the start could not be sent: {response}"}
        return {
            "ok": True,
            "transaction_id": transaction_id,
            "event_type": message.type,
            "query_rounds": rounds,
        }

    def _reached(self, sas, want):
        """The two end states this proof observes.

        `verified` is deliberately absent: nothing here can reach it, so a
        branch for it would be one nothing runs. See
        `level_two_verification.rs`'s header for why, and add it back with
        the assertion that needs it.
        """
        if want == "string":
            return sas.established_sas is not None
        if want == "canceled":
            return sas.canceled
        raise ValueError(f"unknown condition {want!r}")

    async def op_sas_await(self, cmd):
        """Sync, sending whatever nio queues in reply, until the comparison
        reaches the named condition.

        This is the whole driver. nio answers a `start` it received with an
        `accept`, an `accept` with its key, and a key with its own key, by
        appending to `outgoing_to_device_messages`; `sync_forever` would
        post those automatically and this posts them explicitly, so a
        message that was never sent is a visible missing step rather than a
        silent absence.

        `want` is `string` (the short authentication string can be shown),
        `verified`, or `canceled`. The reply always says whether the
        condition was reached, never merely that the call returned.

        **Whatever is queued is posted before the condition is examined**,
        and the order is not incidental: nio decides to cancel while
        handling an incoming event and only queues the cancellation. A loop
        that looked first would report the flow cancelled and return with
        the cancellation still sitting in nio's queue, so the far side would
        never hear about it. That happened, and cost a run.
        """
        transaction_id = cmd["transaction_id"]
        want = cmd["want"]
        deadline = asyncio.get_event_loop().time() + float(cmd.get("timeout_s", 90))

        sent = []
        while True:
            sent.extend(
                message.type for message in self.client.outgoing_to_device_messages
            )
            await self.client.send_to_device_messages()

            sas = self.client.key_verifications.get(transaction_id)
            if sas is not None and self._reached(sas, want):
                reply = {"ok": True, "reached": True, "sent": sent}
                reply.update(self._sas_report(sas))
                return reply
            if asyncio.get_event_loop().time() >= deadline:
                break

            await self.client.sync(timeout=2000, full_state=False)

        sas = self.client.key_verifications.get(transaction_id)
        reply = {
            "ok": True,
            "reached": False,
            "sent": sent,
            # A comparison the far side cancelled is removed from nio's map
            # outright, so "gone" and "still going" are different answers
            # and this says which.
            "known": sas is not None,
        }
        if sas is not None:
            reply.update(self._sas_report(sas))
        return reply

    async def op_sas_commitment_probe(self, cmd):
        """Recompute the commitment the far side sent, in both encodings.

        Here to *attribute* an `m.mismatched_commitment` refusal rather than
        merely report one. nio keeps the commitment it received in the
        `accept` (`Sas.receive_accept_event`) and, when the peer's key
        arrives, compares it against one it computes itself over the same
        two inputs: the peer's public key and the canonical JSON of the
        start message. This recomputes that digest and returns it written
        down both ways, so the Rust side can say which of "the two sides
        hashed different things" and "the two sides wrote the same hash
        differently" actually happened -- and say it from the bytes rather
        than from a string comparison.

        Nothing here is secret: a commitment and a public key are both
        already on the wire.
        """
        transaction_id = cmd["transaction_id"]
        content = self.starts.get(transaction_id)
        if content is None:
            return {
                "ok": False,
                "error": f"this process never opened a comparison with transaction id "
                f"{transaction_id!r}",
            }
        sas = self._sas(transaction_id)
        canonical = Api.to_canonical_json(content)
        digest = hashlib.sha256(cmd["peer_key"].encode() + canonical.encode()).digest()
        return {
            "ok": True,
            # What the far side put in its `m.key.verification.accept`.
            "received": sas.commitment,
            # The same digest, written the two ways.
            "hex": digest.hex(),
            "unpadded_base64": base64.b64encode(digest).decode().rstrip("="),
        }

    # ------------------------------------------------------------------
    # Cross-signing, which matrix-nio 0.26.0 does not implement
    #
    # The Rust side needs to be able to say, with evidence, why an event
    # from this counterparty cannot read anything better than "the sending
    # device carries no signature from its owner". The reason is not in
    # that library and not on the wire: nio has no cross-signing at all.
    # It never publishes a master key, and it drops the ones a homeserver
    # hands it.
    #
    # So this is attribution from inside the counterparty, the same job
    # `sas_commitment_probe` does for the verification proof. Every fact
    # below is computed here, at run time, from the pinned install --
    # never asserted on the Rust side against a version number.
    # ------------------------------------------------------------------

    async def op_identity_probe(self, cmd):
        """What nio sees, and keeps, of an account that has published an identity.

        Four facts, in increasing order of how hard they are to argue with:

        1. what the homeserver actually returned to *nio's own*
           `/keys/query` for that user, read off the raw body;
        2. what nio's own `KeysQueryResponse` retains of it, read off the
           dataclass rather than off documentation;
        3. whether anything in nio can publish a cross-signing identity,
           by looking for the endpoint in its own source;
        4. how many times the installed package mentions the cross-signing
           vocabulary at all.

        Nothing here is secret. A master key and a device key are both
        already public, and only field *names* are returned, never a key.
        """
        import dataclasses
        import pathlib

        import nio as nio_package
        from nio.responses import KeysQueryResponse

        user_id = cmd["user_id"]

        # 1. The raw answer, over nio's own authenticated session.
        method, path, data = Api.keys_query(self.client.access_token, {user_id})
        response = await self.client.send(method, path, data)
        raw = await response.json()
        raw_fields = sorted(raw.keys())
        # Read positively, on the field the whole question turns on, rather
        # than by the absence of something.
        raw_carries_master_key = bool(raw.get("master_keys", {}).get(user_id))

        # 2. What nio keeps of it. `from_dict` is what nio runs on every key
        # query it makes, so this is the real parse and not a description
        # of one.
        parsed = KeysQueryResponse.from_dict(raw)
        parsed_fields = sorted(f.name for f in dataclasses.fields(parsed))

        # 3. Anything that could publish one. Searched for by endpoint
        # rather than by method name, because a name can be anything and an
        # endpoint cannot.
        sources = sorted(pathlib.Path(nio_package.__file__).parent.rglob("*.py"))
        texts = [f.read_text() for f in sources]
        publishes_from = sorted(
            f.name for f, text in zip(sources, texts) if "device_signing/upload" in text
        )

        # 4. The vocabulary, counted rather than characterised.
        vocabulary = (
            "master_key",
            "self_signing",
            "user_signing",
            "cross_signing",
            "cross-signing",
        )
        mentions = sum(text.count(word) for text in texts for word in vocabulary)

        return {
            "ok": True,
            "raw_fields": raw_fields,
            "raw_carries_master_key": raw_carries_master_key,
            "parsed_fields": parsed_fields,
            "publishes_from": publishes_from,
            "vocabulary_mentions": mentions,
            "source_files_read": len(sources),
        }

    async def op_quit(self, cmd):
        if self.client is not None:
            # Logged out, not merely closed: this device's access token must
            # not outlive the test run. The device itself goes with it.
            try:
                await self.client.logout()
            finally:
                await self.client.close()
        return {"ok": True}


async def main():
    party = Party()
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader), sys.stdin
    )

    while True:
        line = await reader.readline()
        if not line:
            return
        command = json.loads(line)
        op = command.get("op")
        handler = getattr(party, f"op_{op}", None)
        if handler is None:
            reply = {"ok": False, "error": f"unknown op {op!r}"}
        else:
            try:
                reply = await handler(command)
            except Exception:  # noqa: BLE001 -- the Rust side asserts on this
                reply = {"ok": False, "error": traceback.format_exc(limit=8)}
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()
        if op == "quit":
            return


if __name__ == "__main__":
    asyncio.run(main())
