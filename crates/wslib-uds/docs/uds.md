# UDS as this crate reads it

The wire facts `wslib-uds` relies on, each pinned by the test named beside it.
Written from knowledge of ISO 14229-1:2020; not checked against the
standard's text, which was not at hand. The first real ECU is the first
independent check.

## Messages

A request is a service id followed by its parameters. A positive response's
first byte is the service id plus 0x40. All multi-byte fields are big-endian.
(`tests/codec.rs`: `a_response_names_the_service_it_answers`)

A negative response is 0x7F, the request's service id and the negative
response code: at least three bytes. Strict decoding takes exactly three
(`a_negative_response_is_three_bytes`); `answers` reads the first three of a
longer one. A response starting 0x7F is never a positive answer, and a service
id from 0xC0 up has no positive response id (`tests/answer.rs`:
`a_response_starting_0x7f_is_never_a_positive_answer`,
`a_service_id_from_0xc0_has_no_positive_answer`).

## The sub-function byte

Services with a sub-function carry it in the byte after the service id: the
value in bits 0-6, and bit 7 the suppressPosRspMsgIndicationBit. The ISO
services with a sub-function are 0x10, 0x11, 0x19, 0x27, 0x28, 0x29, 0x2C,
0x31, 0x3E, 0x83, 0x85, 0x86 and 0x87, modelled or not
(`tests/tables.rs`: `the_table_knows_which_services_carry_a_sub_function`;
`tests/codec.rs`:
`the_suppress_bit_is_recognised_for_every_iso_service_with_a_sub_function`).
A sub-function value is at most 0x7F
(`a_sub_function_cannot_hold_a_value_over_0x7f`).

With the bit set the server sends no positive response. It still sends a
negative one, except that to a functionally addressed request it also
suppresses serviceNotSupported (0x11), subFunctionNotSupported (0x12),
requestOutOfRange (0x31), subFunctionNotSupportedInActiveSession (0x7E) and
serviceNotSupportedInActiveSession (0x7F). If it has sent responsePending, the
final response follows anyway
(`session_control_keeps_the_suppress_bit_apart_from_the_session`,
`tester_present_round_trips_with_and_without_suppression`;
`tests/pairing.rs`: `a_suppressed_request_still_pairs_with_a_negative_response`,
`silence_after_response_pending_times_out_even_when_suppressed`).

## Which response answers which request

`answers(request, response)` decides on leading bytes alone, and the client,
the tracker and the scan verdicts all use it (`tests/answer.rs`):

- A negative response answers the request whose service id it names.
- A positive response carries the service id plus 0x40 and echoes what the
  request identified, so far as the request has it: the sub-function value
  without the suppress bit for a sub-function service; for 0x22 one of the
  requested DIDs; for 0x2E and 0x2F the DID; for 0x31 the sub-function and the
  routine id; for 0x36 the block sequence counter. A bare service id is
  answered by its positive id alone.
- A positive answer that then fails strict decoding still resolves the request,
  as malformed (`tests/client.rs`:
  `a_positive_answer_that_fails_strict_decoding_still_resolves_the_request_as_malformed`;
  `tests/pairing.rs`:
  `a_positive_answer_that_fails_strict_decoding_ends_the_transaction_malformed`).
  The client still applies what the service confirms, in the safe direction:
  a malformed 0x50 enters the echoed session and a malformed 0x51 returns to
  the default session, each locking security and restoring the default
  timing; nothing unlocks without a well-formed key acceptance
  (`a_malformed_ecu_reset_answer_still_returns_session_security_and_timing_to_the_defaults`,
  `a_key_answer_that_does_not_echo_the_key_sub_function_does_not_unlock`).
  Anything else answers nothing and changes no state
  (`a_reply_that_does_not_echo_the_requested_did_or_routine_is_unexpected_and_changes_nothing`).
  A request that goes unanswered, by timeout or abandonment, may still have
  been acted on, so the client moves the same way: after 0x10 or 0x11 it
  locks security and no longer knows the session, and after 0x27 it locks
  security. While the session is unknown it sends no keep-alive, since one
  could hold a session the ECU was never meant to stay in; after S3 without a
  request the ECU is in the default session again, and so is the client
  (`a_session_change_or_reset_that_goes_unanswered_locks_security_and_leaves_the_session_unknown`,
  `a_security_access_that_goes_unanswered_locks_security_and_keeps_the_session`,
  `an_unknown_session_gets_no_keep_alive_and_becomes_the_default_at_s3`).
  A suppressed 0x27 that draws no refusal by P2 is not known to have
  unlocked anything, so it too locks security
  (`a_suppressed_security_access_that_draws_no_refusal_locks_security`).
- A refusal of a tester present (0x7F 0x3E) within P2 of the client's
  keep-alive belongs to the keep-alive, which was always sent before any
  caller request still open: it is reported as a refused keep-alive and never
  closes the caller's request
  (`a_refusal_of_the_keep_alive_is_its_own_event_and_never_closes_the_callers_request`).
  responsePending (0x78) to the keep-alive is no refusal: the keep-alive is
  then owed a final answer, refusal or positive (0x7E 0x00), for P2* from
  then, and that answer is the keep-alive's before any caller request is
  matched
  (`response_pending_to_the_keep_alive_is_no_refusal_and_holds_its_window_open_to_p2_star`,
  `the_keep_alives_final_answer_after_response_pending_is_the_keep_alives`).
  A tester present the caller sends after that responsePending ends the wait,
  so its own answer is its own
  (`once_the_keep_alive_drew_response_pending_a_tester_present_from_the_caller_ends_its_window`).
  A keep-alive interval of zero sends none
  (`a_zero_keep_alive_interval_sends_no_keep_alive`).
- In a capture, a suppressed tester present (0x3E 0x80) while a request is
  still owed a response is a keep-alive: it is reported at once as its own
  suppressed transaction and leaves the open request alone
  (`tests/pairing.rs`:
  `a_keep_alive_tester_present_does_not_supersede_a_request_owed_a_response`).
  A request that suppressed its positive response, and drew no
  responsePending, is owed nothing but may still be refused: it stays open to
  the timeout whatever follows it, and ends suppressed if no refusal comes
  (`a_suppressed_request_stays_open_to_its_timeout_so_a_late_refusal_still_pairs_with_it`,
  `a_suppressed_request_ends_suppressed_at_its_timeout_not_when_the_next_request_comes`).
  A response goes to the newest open request it answers that is owed a
  response, or failing that to the newest suppressed one it answers
  (`a_response_pairs_with_the_newest_request_owed_one_before_any_suppressed_one`,
  `of_two_suppressed_requests_to_one_service_a_refusal_pairs_with_the_newer`).
  At most 32 requests stay open; a new one beyond that supersedes the oldest,
  which can only be a suppressed one, so stamps that run backwards cannot grow
  the tracker
  (`the_open_requests_are_capped_by_closing_the_oldest_suppressed_one`).
  The tracker ends an open request that has timed out before it reads the
  next message, by that message's time
  (`a_reply_after_the_timeout_ends_the_request_timed_out_and_is_itself_unsolicited`,
  `a_new_request_long_after_the_last_closes_it_timed_out_not_superseded`).

## Layouts

| Service | Request after the id | Positive response after its id |
| --- | --- | --- |
| 0x10 DiagnosticSessionControl | session | session, then optionally P2server_max (2 bytes, 1 ms) and P2*server_max (2 bytes, 10 ms) |
| 0x11 ECUReset | reset type | reset type, optional power-down time (1 byte) |
| 0x14 ClearDiagnosticInformation | group of DTC (3 bytes), optional memory selection | nothing |
| 0x19 ReadDTCInformation | report type, then by type: 0x01/0x02 status mask; 0x04/0x06 DTC (3) and record number; 0x0A nothing | report type; 0x01 availability mask, format, count (2); 0x02/0x0A availability mask then DTC (3) and status per record |
| 0x22 ReadDataByIdentifier | one or more DIDs (2 bytes each) | each DID followed by its data |
| 0x23 ReadMemoryByAddress | addressAndLengthFormatIdentifier, address, size | data |
| 0x27 SecurityAccess | odd sub-function requests a seed; even sends the key | sub-function, then the seed (all zero when already unlocked) |
| 0x28 CommunicationControl | control type, communication type, optional node id (2) | control type |
| 0x2E WriteDataByIdentifier | DID, data (at least 1 byte) | DID |
| 0x2F InputOutputControlByIdentifier | DID, control option record | DID, control status record |
| 0x31 RoutineControl | 0x01 start, 0x02 stop, 0x03 results; routine id (2); options | sub-function, routine id, status record |
| 0x34 RequestDownload / 0x35 RequestUpload | data format, addressAndLengthFormatIdentifier, address, size | lengthFormatIdentifier (high nibble the width, low nibble 0), maxNumberOfBlockLength |
| 0x36 TransferData | block sequence counter, data | block sequence counter, data |
| 0x37 RequestTransferExit | optional parameters | optional parameters |
| 0x3E TesterPresent | sub-function 0x00 | 0x00 |
| 0x85 ControlDTCSetting | 0x01 on, 0x02 off, optional record | setting |

Each row is pinned by its round-trip test in `tests/codec.rs`. The
addressAndLengthFormatIdentifier's high nibble is the size's width and its low
nibble the address's; this crate takes widths of 1 to 8 bytes and refuses
others (`the_address_and_length_format_identifier_sets_each_fields_width`,
`a_zero_or_over_eight_byte_width_is_refused`). A memory range or block length
cannot be built with a width outside that or a value too wide for its width
(`a_memory_range_or_block_length_cannot_hold_a_width_or_value_it_cannot_encode`).
A DTC or group of DTCs is three bytes and cannot be built over 24 bits
(`a_dtc_cannot_hold_more_than_24_bits`). A 0x19 report type with no variant of
its own cannot be over 0x7F, where it would set the suppress bit, or one of
the typed ones
(`an_untyped_report_type_cannot_carry_the_suppress_bit_or_a_typed_report_type`);
in a 0x59 response it cannot be 0x01, 0x02 or 0x0A
(`an_untyped_response_report_type_cannot_be_a_typed_one`). A 0x22 request
names at least one DID, and a 0x2E or 0x2F request carries at least one data
byte (`a_did_read_write_or_io_control_cannot_be_empty`).
Several DIDs' data cannot be split without each DID's length, so a 0x62
response keeps everything after the first DID together
(`read_data_by_identifier_takes_several_dids_in_one_request`). Any other
service is kept as its id and bytes in `Other`
(`any_other_service_is_kept_byte_for_byte`); an `Other` naming a modelled
service decodes as that service's variant. Every message the decoder accepts
re-encodes byte for byte
(`every_two_byte_message_decodes_without_panic_and_re_encodes_exactly`,
`arbitrary_messages_decode_without_panic_and_re_encode_exactly`), and every
request and response, with `Other` holding only a service this crate does not
model, decodes back from its encoding (`tests/round_trip.rs`:
`every_request_and_response_decodes_back_from_its_encoding`).

## Response pending and timing

Negative response code 0x78 (requestCorrectlyReceivedResponsePending) says the
server is still working: the client's deadline moves from P2 to P2*, and more
than one may come before the final response
(`tests/client.rs`: `response_pending_moves_the_deadline_to_p2_star`;
`tests/pairing.rs`:
`response_pending_answers_are_counted_and_the_final_response_ends_the_transaction`).
Nothing caps how many may come; the client's caller gives up with `abandon`
(`abandoning_the_outstanding_request_frees_the_client_however_long_pending_runs`).
After a 0x78 the server owes a final response, so silence after one is a
timeout, never a suppressed success; it is unanswered, as above
(`silence_after_response_pending_is_a_timeout_even_when_the_positive_response_was_suppressed`,
`a_suppressed_session_change_that_drew_response_pending_and_then_silence_times_out_unknown`).
No timing value panics: a wait too long for an `Instant` to hold never ends
(`no_timing_however_long_panics_and_a_wait_too_long_to_represent_never_ends`).

P2 is how long the server may take to start its response (default 50 ms),
P2* how long after a responsePending (default 5000 ms). A positive
session-control response reports both, and the client adopts them
(`a_positive_session_control_sets_the_session_and_takes_p2_and_p2_star`).
Every session change without a readable timing record, ECU reset and S3 expiry
among them, returns them to the defaults the client was built with
(`p2_and_p2_star_return_to_the_defaults_on_s3_expiry`,
`p2_and_p2_star_return_to_the_defaults_on_ecu_reset`,
`p2_and_p2_star_return_to_the_defaults_on_a_default_session_answer_with_no_timing`,
`a_malformed_session_answer_still_changes_the_session_with_default_timing`).

S3 (5000 ms) is how long a server stays in a non-default session without a
request before returning to the default session. A tester present with the
suppress bit, 0x3E 0x80, holds it
(`a_quiet_non_default_session_is_kept_alive_with_a_suppressed_tester_present`,
`s3_expiry_returns_the_client_to_the_default_session`). S3 does not run while
a request is outstanding; it counts from when the request resolves, by answer,
timeout or abandonment
(`s3_counts_from_when_a_request_resolves_so_a_keep_alive_comes_before_expiry`).
Every session change,
to the session already active included, and an ECU reset lock security again
(`a_session_change_resets_the_security_state`,
`an_ecu_reset_returns_to_the_default_session`).

## Negative response order

A server checks a request in this order and answers the first check it fails:
service supported (0x11), service supported in the active session (0x7F),
minimum length (0x13), sub-function supported (0x12), sub-function supported
in the active session (0x7E); then, for a service that names a DID or routine,
whether it exists (0x31); then security (0x33), full length (0x13) and the
ranges of its data (0x31). The simulated ECU follows it; it
gates no sub-function by session, so it never sends 0x7E
(`tests/ecu.rs`: `negative_responses_come_in_the_standards_order`).

## Safety

A bare service id has the class its service has with the sub-function unknown:
a non-conforming server can act on one.

A client sends nothing above its ceiling: read-only unless it was built with
`write` and a higher one. A scan run through a client is bounded by the lower
of the scan's class and the client's ceiling (`tests/client_write.rs`:
`by_default_a_client_refuses_a_state_changing_request_and_sends_nothing`,
`a_state_changing_ceiling_refuses_destructive_and_vendor_requests_and_keeps_the_session_alive`;
`tests/service_scan_write.rs`:
`a_scan_through_a_client_sends_only_up_to_the_lower_of_the_two_ceilings`).

| Request | Safety | Test (`tests/safety.rs`) |
| --- | --- | --- |
| 0x19, 0x22 | read-only | `reading_dtcs_and_data_is_read_only` |
| 0x3E | read-only | `tester_present_is_read_only` |
| 0x31 with sub-function 0x03 | read-only | `routine_start_and_stop_are_destructive_and_its_results_read_only` |
| 0x10 | state-changing | `session_control_is_state_changing` |
| 0x11 | state-changing | `ecu_reset_is_state_changing` |
| 0x23: memory-mapped registers can have side effects, and a bad address can fault the ECU | state-changing | `reading_memory_is_state_changing_for_its_side_effects` |
| 0x27 | state-changing | `security_access_is_state_changing` |
| 0x28 | state-changing | `communication_control_is_state_changing` |
| 0x85 | state-changing | `control_dtc_setting_is_state_changing` |
| 0x14 | destructive | `clearing_dtcs_is_destructive` |
| 0x2E | destructive | `writing_data_is_destructive` |
| 0x2F | destructive | `input_output_control_is_destructive` |
| 0x31 start, stop, any other sub-function or none | destructive | `routine_start_and_stop_are_destructive_and_its_results_read_only` |
| 0x34, 0x35, 0x36, 0x37 | destructive | `download_upload_and_transfer_are_destructive` |
| Any other service, ISO or vendor; an empty message | destructive | `other_iso_services_vendor_services_and_an_empty_message_are_destructive` |
| A bare id, by the rows above | as its service | `a_bare_service_id_has_its_services_class_with_the_sub_function_unknown` |

## Scan verdicts

- Address: the probe is a tester present (0x3E 0x00), and a positive or
  negative answer to it, as `answers` judges, means an ECU (`tests/scan.rs`:
  `an_address_scan_finds_the_addresses_that_answer_positive_or_negative`,
  `an_address_counts_as_an_ecu_only_for_an_answer_to_its_tester_present`).
  The 11-bit range is 0x700 to 0x7FF; 29-bit normal fixed addressing is
  0x18DA, target address, source address.
- Service, by bare id, over the ISO ids other than 0x37: without `write` only
  the read-only bare ids (0x19, 0x22, 0x3E); with `write`, those up to the class
  the caller allows (`without_write_a_service_scan_probes_only_bare_ids_that_are_read_only`;
  `tests/service_scan_write.rs`:
  `a_service_scan_never_offers_a_probe_above_the_highest_class_allowed`).
  serviceNotSupported (0x11) means absent; serviceNotSupportedInActiveSession
  (0x7F) present but not in this session; busyRepeatRequest (0x21) busy and
  re-offered; any other refusal present. A positive answer means the server
  acted on a bare id: the plan records it as executed, and stops if the bare
  id's class is above read-only (`service_verdicts_follow_the_refusal_code`,
  `a_positive_answer_to_a_read_only_bare_id_is_recorded_executed_and_the_scan_carries_on`,
  `a_positive_answer_to_a_bare_id_above_read_only_is_recorded_executed_and_stops_the_scan`).
- DID: a 0x62 echoing the DID is present with its data's length;
  requestOutOfRange (0x31) absent; securityAccessDenied (0x33) locked; 0x7F not
  in this session; 0x21 busy; anything else inconclusive
  (`a_did_scan_reports_present_absent_and_locked_through_a_read_only_client`,
  `did_verdicts_follow_the_reply`).
- Session, behind `write`: a 0x50 echoing the session is supported;
  subFunctionNotSupported (0x12) unsupported;
  subFunctionNotSupportedInActiveSession (0x7E) not reachable from here;
  conditionsNotCorrect (0x22); 0x33 locked. After any probe of a non-default
  session that did not end in a definite refusal (silence, an undecodable or
  mismatched reply, or a supported answer) the plan sends 0x10 0x01 before the
  next probe (`tests/session_scan.rs`:
  `the_default_session_is_restored_after_any_probe_that_did_not_end_in_a_definite_refusal`).
  A restore not answered positively stops the plan, with a finding that the
  ECU may still be in the session probed
  (`a_refused_or_silent_restore_stops_the_plan_with_the_session_the_ecu_may_still_be_in`).
  The programming session (0x02) is probed only when asked
  (`the_programming_session_is_probed_only_when_asked_for`).
