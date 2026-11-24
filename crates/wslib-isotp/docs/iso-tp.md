# ISO-TP: the wire facts this crate relies on

Written from knowledge of ISO 15765-2:2016. It has not been checked against
the paid text. Each fact names the test that pins it; a test name is
`module::name` for a unit test in `src/`, or `file::name` under `tests/`.

## Frames and their PCI

A frame's first byte, after any address byte, is its protocol control
information (PCI). Its high nibble is the frame type: 0 single, 1 first,
2 consecutive, 3 flow control. 4 to F are reserved, and such a frame is not
ISO-TP.

- `pci::classifies_by_the_high_nibble`
- `pci::refuses_an_empty_frame_a_reserved_type_and_an_fd_length`

### Single frame (SF)

- In a frame of 8 bytes or fewer, the low nibble is the message length, 1 to
  7 (1 to 6 behind an address byte). A length of 0, or one the frame cannot
  carry, is not a message.
  `framing::a_single_frame_of_8_bytes_or_fewer_carries_its_length_in_the_low_nibble`,
  `segment::a_single_frame_is_one_plus_its_length`,
  `segment::extended_addressing_leaves_6_bytes_in_a_classic_single_frame`,
  `reassemble::a_single_frame_of_length_0_or_over_7_is_ignored`
- In a CAN FD frame over 8 bytes, the PCI byte is `0x00` and the length is
  the next byte. A low-nibble length in such a frame is not a message, nor
  is an escaped one in a frame of 8 bytes or fewer.
  `framing::a_single_frame_over_8_bytes_escapes_its_length_into_the_second_byte`,
  `segment::a_can_fd_single_frame_over_7_bytes_escapes_its_length`
- A sender uses the short form whenever the message fits a classic single
  frame, and the escaped form only above that.
  `segment::a_can_fd_single_frame_over_7_bytes_escapes_its_length`

### First frame (FF)

- `0x1L LL`: a 12-bit length, 1 to 4095. The frame is the sender's full
  transmit data length (8 on classic CAN).
  `segment::the_first_frame_carries_a_12_bit_length`,
  `segment::can_fd_first_and_consecutive_frames_fill_the_tx_data_length`,
  `reassemble::a_first_frame_under_8_bytes_is_ignored`
- The length must exceed what a single frame of the same frame length could
  carry, so it is at least 8 on an 8-byte frame (7 behind an address byte),
  and at least CAN_DL − 1 (CAN_DL − 2 behind an address byte) on a frame of
  CAN_DL bytes above 8.
  `framing::a_first_frames_length_must_exceed_what_a_single_frame_of_its_size_carries`,
  `reassemble::a_first_frame_length_under_8_is_ignored`
- Escaped: `0x10 0x00` then a 32-bit big-endian length, used only for a
  message over 4095 bytes. An escaped length of 4095 or less is not a first
  frame.
  `segment::a_message_over_4095_bytes_takes_an_escaped_first_frame`,
  `framing::an_escaped_first_frame_is_read_only_above_4095_and_with_a_cap_above_4095`
- A receiver with no room answers a first frame with an overflow flow
  control and does not start the message.
  `reassemble::a_first_frame_over_the_message_cap_is_answered_with_overflow`
- The announced length is never trusted to size a buffer: a receiver
  reserves at most 4095 bytes up front and grows as frames arrive.
  `reassemble::an_announced_length_reserves_at_most_4095_bytes`,
  `tap::an_announced_length_reserves_at_most_4095_bytes`
- A single or first frame, valid or not, ends the message being received.
  `reassemble::an_invalid_single_or_first_frame_ends_the_message_and_is_ignored`,
  `reassemble::a_new_first_frame_aborts_a_message_and_starts_over`

### Consecutive frame (CF)

- `0x2N`: N is the sequence number. The first CF after a first frame is 1,
  and it wraps from 15 to 0.
  `segment::the_sequence_number_starts_at_1_and_wraps_to_0`,
  `reassemble::the_sequence_number_wraps_on_receive`
- Every CF but the last is as long as the first frame was; the last carries
  the rest. A CF out of sequence or carrying too little aborts the message.
  A CF longer than the first frame is not part of the message and is
  ignored. On classic CAN no frame is longer than 8 bytes, so this never
  arises.
  `reassemble::a_can_fd_receiver_reads_consecutive_frames_as_long_as_the_first`,
  `reassemble::a_consecutive_frame_out_of_sequence_aborts`,
  `reassemble::a_short_consecutive_frame_before_the_last_aborts`,
  `reassemble::a_consecutive_frame_longer_than_the_first_frame_is_ignored`,
  `tap::a_consecutive_frame_longer_than_the_first_frame_is_skipped`

### Flow control (FC)

- `0x3S BS STmin`. S is 0 continue to send, 1 wait, 2 overflow; 3 to F are
  reserved, and a sender given one fails the send.
  `flow_control::encodes_three_bytes`,
  `flow_control::round_trips_every_status`,
  `flow_control::tells_a_reserved_status_apart`
- BS is the consecutive frames per block, 0 for all of them. After a block
  but the last, the receiver sends another flow control.
  `reassemble::a_block_size_asks_for_flow_control_after_each_block_but_the_last`,
  `reassemble::a_block_size_counts_from_each_flow_control`
- STmin `0x00` to `0x7F` is that many milliseconds; `0xF1` to `0xF9` is 100
  to 900 µs. The rest is reserved, and read as 127 ms.
  `flow_control::decodes_milliseconds`,
  `flow_control::decodes_hundreds_of_microseconds`,
  `flow_control::decodes_every_reserved_value_as_127_ms`
- STmin spaces consecutive frames. The first CF after a flow control is not
  held back by it.
  `testing::responses_honour_the_requesters_block_size_and_st_min`

## Addressing

- Normal addressing: the CAN id alone addresses the frame, and the PCI is the
  first byte.
- Extended addressing puts a target address byte before the PCI; mixed
  addressing puts an address extension byte there. On the wire the two are
  the same: one byte, then the PCI. Each end sends its own byte and expects
  the other's, which may differ.
  `framing::extended_addressing_prefixes_every_sent_frame_with_its_tx_byte`,
  `framing::extended_addressing_reads_only_frames_carrying_its_rx_byte`,
  `framing::mixed_addressing_is_carried_on_the_wire_as_extended_is`
- The address byte costs every frame one byte of payload.
  `segment::extended_addressing_leaves_6_bytes_in_a_classic_single_frame`

## CAN FD

- A sender's transmit data length (TX_DL) is 8, 12, 16, 20, 24, 32, 48 or 64.
  `framing::the_can_fd_lengths_are_the_eight_iso_tp_may_send_with`
- A frame over 8 bytes is padded up to the next valid CAN FD length. A frame
  of 8 bytes or fewer may go unpadded.
  `framing::a_can_fd_frame_over_8_bytes_is_filled_to_the_next_valid_length`,
  `framing::padding_fills_a_frame_of_8_or_fewer_to_8`
- The receiver takes the first frame's length as the length of every
  consecutive frame but the last.
  `reassemble::a_can_fd_receiver_reads_consecutive_frames_as_long_as_the_first`

## Timing

- N_As, N_Bs and N_Cr default to 1 s: the sender's wait for its frame to go,
  its wait for a flow control, and the receiver's wait for the next
  consecutive frame.
  `link::the_defaults_are_iso_tp_s`
- A wait flow control restarts N_Bs.
  `link::a_wait_restarts_n_bs_and_a_cts_then_sends`
- A consecutive frame at or after N_Cr ends the message.
  `link::a_gap_over_n_cr_aborts_the_message`

## This crate's choices

Where the standard leaves a value open, or where this crate reads it one way
of several, it says so here.

- An escaped single frame is read at any length its frame carries, even one
  a shorter frame would have carried: a tap and a tester should read what
  real senders put on the wire, and senders that pad short payloads to
  their full transmit length are common. The `Segmenter` still sends the
  shortest valid frame.
  `framing::an_escaped_single_frame_is_read_at_any_length_its_frame_carries`
- Padding of a classic frame is off by default and read either way. The
  byte that fills a CAN FD frame over 8 bytes when none is set is `0xCC`.
  `framing::padding_fills_a_frame_of_8_or_fewer_to_8`,
  `reassemble::round_trips_padded`
- A link survives 10 waits in a row; the 11th fails the send.
  `link::ten_waits_then_cts_succeeds`, `link::the_eleventh_wait_in_a_row_fails_the_send`
- A framing whose `max_message` is 4095 or less ignores an escaped first
  frame rather than answering it with an overflow, as 0.1 did.
  `framing::an_escaped_first_frame_is_read_only_above_4095_and_with_a_cap_above_4095`
- A consecutive frame longer than the first frame is ignored, not taken as
  an error that aborts the message.
  `reassemble::a_consecutive_frame_longer_than_the_first_frame_is_ignored`

### The tap

- A tapped message times out after N_Cr or more with no frame that restarts
  its timer, judged on the time of any later frame on the bus. The sender's
  frames restart it, and so does a flow control the message is waiting for:
  after the first frame or at the end of a block, a wait included while
  within the wait limit. Any consecutive frame ends the wait for flow
  control until its block, if it has one, runs out. A flow control arriving
  when none is due, mid-block or after a continue-to-send with no
  consecutive frame since, is recorded but restarts nothing, so a receiver
  cannot hold a dead message open.
  `tap::a_gap_of_n_cr_or_more_since_the_senders_last_frame_times_the_message_out_on_any_later_frame`,
  `tap::a_consecutive_frame_ends_the_wait_for_flow_control_so_a_later_one_restarts_nothing`,
  `tap::a_wait_chain_longer_than_n_cr_keeps_the_message_while_each_wait_is_due`,
  `tap::a_continue_to_send_when_none_is_due_restarts_nothing`,
  `tap::a_flow_control_at_the_end_of_a_block_restarts_the_timer`
- Frame times are whole microseconds from any fixed origin. A frame stamped
  before the timer started is no gap at all.
  `tap::a_frame_stamped_before_the_timer_started_times_nothing_out`
- One wait more than the tap's wait limit (10 by default, as the link's)
  drops the message; a continue-to-send restarts the count. A message keeps
  its first 64 flow controls and counts them all.
  `tap::one_wait_past_the_wait_limit_drops_the_message`,
  `tap::a_continue_to_send_restarts_the_wait_count`,
  `tap::the_flow_controls_kept_per_message_are_capped_and_all_are_counted`
- A frame on the conversation's id that does not lead with that side's
  address byte is not the conversation's. With one id both ways, the address
  bytes tell the sides apart; a tap that cannot tell them apart is refused.
  `tap::a_frame_on_the_pairs_id_with_another_address_byte_is_ignored_as_another_id_is`,
  `tap::one_id_both_ways_is_told_apart_by_its_address_bytes`,
  `tap::a_config_whose_sides_cannot_be_told_apart_is_refused`

### Detection

- A first frame is open to answers for the window from its own time. A wait
  from an id already a candidate, and the first continue-to-send, extend it
  from their own time; nothing else does. An open first frame closes when
  the window passes before its first consecutive frame, when its own id
  sends a frame that cannot continue it, or when it completes. It keeps at
  most 4 candidate ids.
  `detect::the_window_runs_from_the_first_frame_and_flow_controls_do_not_hold_it_open`,
  `detect::waits_from_a_candidate_extend_the_window`,
  `detect::a_flow_control_outside_the_window_answers_nothing`
- A flow control within the window of several open first frames is a
  candidate answer to each. A sender's answering id is settled across all
  its completed messages: an id with frames no ISO-TP frame could be loses
  to one without; then the id that is a candidate for the most of them wins
  if it is a candidate for all of them or no rival is a candidate more than
  once, and no rival ties it. A message whose candidates do not include the
  winner, or a sender with no winner, counts as ambiguous. Two ECUs
  answered by two testers at once, each once, report neither pair. A flow
  control that ends up answering no completed message is a sequence break.
  `detect::two_first_frames_answered_from_two_ids_at_once_pair_neither`,
  `detect::a_first_frame_look_alike_between_a_first_frame_and_its_flow_control_takes_nothing`,
  `detect::a_stray_flow_control_once_loses_to_the_id_answering_every_message`,
  `detect::a_stray_from_an_id_carrying_non_iso_tp_frames_loses_even_once`
- Each id is read twice: with normal addressing, and, if its frames lead
  with at most 8 distinct bytes, with that byte as an address, one entry per
  byte. It keeps the reading under which more of its exchanges complete,
  normal on a tie. So an address byte of `0x00` to `0x3F`, which also reads
  as a PCI, is still found, and a counter in the first byte never splits an
  id.
  `detect::an_address_byte_that_also_reads_as_normal_pci_is_found_from_completed_exchanges`,
  `detect::a_shared_tester_id_addressing_several_targets_pairs_each_target`,
  `detect::an_id_with_more_leading_bytes_than_the_cap_is_one_entry`,
  `detect::a_million_frames_over_200_ids_stay_one_entry_per_id`
- What detection cannot do: call an id carrying only single frames ISO-TP;
  separate two senders answered by two ids at once when nothing later
  repeats one of the pairings; find an addressed tester that talks to more
  than 8 targets on one id; or find an exchange whose first flow control
  comes later than the window.
