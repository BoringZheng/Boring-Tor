/* Copyright (c) 2019-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file sendme.c
 * \brief Code that is related to SENDME cells both in terms of
 *        creating/parsing cells and handling the content.
 */

// For access to cpath pvt_crypto field.
#define SENDME_PRIVATE
#define CRYPT_PATH_PRIVATE

#include "core/or/or.h"

#include "app/config/config.h"
#include "core/crypto/relay_crypto.h"
#include "core/mainloop/connection.h"
#include "core/or/cell_st.h"
#include "core/or/crypt_path.h"
#include "core/or/circuitlist.h"
#include "core/or/circuituse.h"
#include "core/or/or_circuit_st.h"
#include "core/or/relay.h"
#include "core/or/relay_msg.h"
#include "core/or/sendme.h"
#include "core/or/congestion_control_common.h"
#include "core/or/congestion_control_flow.h"
#include "feature/nodelist/networkstatus.h"
#include "lib/ctime/di_ops.h"
#include "lib/crypt_ops/crypto_digest.h"
#include "lib/fs/mmap.h"
#include "lib/string/util_string.h"
#include "trunnel/sendme_cell.h"

#define PREDICTIVE_SENDME_ADVANCE_CELLS 2
#define PREDICTIVE_SENDME_SAFE_CELLS 49
#define RELAY_CELL_PADDING_GAP 4
#define RELAY_CELL_RANDOM_PADDING_LEN 16

typedef struct predictive_sendme_state_t {
  tor_mmap_t *file;
  const circuit_t *circuit;
  const crypt_path_t *layer_hint;
  streamid_t stream_id;
  size_t next_file_offset;
  unsigned int predictable_cells;
  unsigned int http_header_match;
  bool initialized;
  bool synced;
  bool prediction_pending;
  bool compatibility_logged;
  bool disabled;
} predictive_sendme_state_t;

static predictive_sendme_state_t predictive_sendme_state;

STATIC bool
predict_v0_data_tag(const crypto_digest_t *current_digest,
                    streamid_t stream_id,
                    const uint8_t *data,
                    size_t data_len,
                    unsigned int cell_count,
                    uint8_t *tag_out)
{
  const size_t payload_len =
    relay_cell_max_payload_size(RELAY_CELL_FORMAT_V0, RELAY_COMMAND_DATA);
  crypto_digest_t *predicted_digest = NULL;
  relay_msg_t msg;
  cell_t cell;
  bool success = false;

  tor_assert(current_digest);
  tor_assert(data);
  tor_assert(tag_out);

  if (stream_id == 0 || cell_count == 0 ||
      data_len < payload_len * cell_count) {
    return false;
  }

  predicted_digest = crypto_digest_dup(current_digest);
  if (predicted_digest == NULL) {
    return false;
  }

  memset(&msg, 0, sizeof(msg));
  msg.command = RELAY_COMMAND_DATA;
  msg.stream_id = stream_id;
  msg.length = payload_len;

  for (unsigned int i = 0; i < cell_count; ++i) {
    msg.body = data + i * payload_len;
    if (relay_msg_encode_cell(RELAY_CELL_FORMAT_V0, &msg, &cell) < 0) {
      goto done;
    }
    crypto_digest_add_bytes(predicted_digest, (char *) cell.payload,
                            CELL_PAYLOAD_SIZE);
  }

  crypto_digest_get_digest(predicted_digest, (char *) tag_out,
                           SENDME_TAG_LEN_TOR1);
  success = true;

 done:
  crypto_digest_free(predicted_digest);
  return success;
}

static predictive_sendme_state_t *
get_predictive_sendme_state(void)
{
  predictive_sendme_state_t *state = &predictive_sendme_state;

  if (state->initialized) {
    return state->disabled ? NULL : state;
  }
  state->initialized = true;

  const char *path = getenv("TOR_PREDICTIVE_SENDME_FILE");
  if (path == NULL || path[0] == '\0') {
    state->disabled = true;
    return NULL;
  }
  state->file = tor_mmap_file(path);
  if (state->file == NULL || state->file->size == 0) {
    log_warn(LD_PROTOCOL, "Unable to map predictive SENDME input file; "
                          "predictor disabled");
    state->disabled = true;
    return NULL;
  }

  log_notice(LD_PROTOCOL,
             "Predictive SENDME enabled with advance_cells=%d version=%s",
             PREDICTIVE_SENDME_ADVANCE_CELLS,
             getenv("TOR_SENDME_V0_TEST") != NULL ? "v0" : "v1");
  return state;
}

static void
disable_predictive_sendme(predictive_sendme_state_t *state,
                          const char *reason)
{
  tor_assert(state);
  tor_assert(reason);

  log_notice(LD_PROTOCOL, "Predictive SENDME disabled: %s", reason);
  state->disabled = true;
}

static bool
predictive_sendme_sync(predictive_sendme_state_t *state,
                       circuit_t *circ,
                       crypt_path_t *layer_hint,
                       const relay_msg_t *msg)
{
  static const uint8_t header_end[] = "\r\n\r\n";
  const uint8_t *file_start = (const uint8_t *) state->file->data;
  for (size_t i = 0; i < msg->length; ++i) {
    if (msg->body[i] == header_end[state->http_header_match]) {
      ++state->http_header_match;
    } else {
      state->http_header_match = msg->body[i] == header_end[0] ? 1 : 0;
    }
    if (state->http_header_match != ARRAY_LENGTH(header_end) - 1) {
      continue;
    }

    const size_t body_offset = i + 1;
    const size_t body_len = msg->length - body_offset;
    state->http_header_match = 0;
    if (body_len > state->file->size ||
        tor_memneq(file_start, msg->body + body_offset, body_len)) {
      return false;
    }

    state->circuit = circ;
    state->layer_hint = layer_hint;
    state->stream_id = msg->stream_id;
    state->next_file_offset = body_len;
    state->synced = true;
    log_notice(LD_PROTOCOL,
               "Predictive SENDME synchronized to HTTP response body");
    return true;
  }
  return false;
}

static void
predictive_sendme_note_data(circuit_t *circ,
                            crypt_path_t *layer_hint,
                            const relay_msg_t *msg)
{
  predictive_sendme_state_t *state = get_predictive_sendme_state();
  if (state == NULL || !CIRCUIT_IS_ORIGIN(circ) || layer_hint == NULL ||
      msg == NULL || msg->command != RELAY_COMMAND_DATA ||
      msg->stream_id == 0) {
    return;
  }

  if (!state->compatibility_logged) {
    log_notice(LD_PROTOCOL, "Predictive SENDME DATA format=%d crypto_kind=%d",
               layer_hint->relay_cell_format, layer_hint->pvt_crypto.kind);
    state->compatibility_logged = true;
  }

  if (
      layer_hint->relay_cell_format != RELAY_CELL_FORMAT_V0 ||
      layer_hint->pvt_crypto.kind != RCK_TOR1) {
    return;
  }

  if (!state->synced) {
    if (state->circuit != circ || state->layer_hint != layer_hint ||
        state->stream_id != msg->stream_id) {
      state->circuit = circ;
      state->layer_hint = layer_hint;
      state->stream_id = msg->stream_id;
      state->http_header_match = 0;
    }
    if (!predictive_sendme_sync(state, circ, layer_hint, msg)) {
      return;
    }
  } else if (state->circuit != circ || state->layer_hint != layer_hint) {
    return;
  } else if (state->stream_id != msg->stream_id) {
    disable_predictive_sendme(state, "interleaved data stream");
    return;
  } else {
    if (state->next_file_offset > state->file->size ||
        msg->length > state->file->size - state->next_file_offset ||
        tor_memneq(state->file->data + state->next_file_offset,
                   msg->body, msg->length)) {
      disable_predictive_sendme(state, "fixed stream content mismatch");
      return;
    }
    state->next_file_offset += msg->length;
  }

  const size_t max_payload =
    relay_cell_max_payload_size(RELAY_CELL_FORMAT_V0, RELAY_COMMAND_DATA);
  const size_t random_payload_limit = max_payload -
    RELAY_CELL_PADDING_GAP - RELAY_CELL_RANDOM_PADDING_LEN;
  if (msg->length <= random_payload_limit) {
    state->predictable_cells = PREDICTIVE_SENDME_SAFE_CELLS;
    log_info(LD_PROTOCOL, "Predictive SENDME observed random-padding cell; "
                          "safe_cells=%u", state->predictable_cells);
  } else if (state->predictable_cells > 0) {
    --state->predictable_cells;
  }
}

/**
 * Return true iff tag_len is some length we recognize.
 */
static inline bool
tag_len_ok(size_t tag_len)
{
  return tag_len == SENDME_TAG_LEN_CGO || tag_len == SENDME_TAG_LEN_TOR1;
}

/* Return the minimum version given by the consensus (if any) that should be
 * used when emitting a SENDME cell. */
STATIC int
get_emit_min_version(void)
{
  return networkstatus_get_param(NULL, "sendme_emit_min_version",
                                 SENDME_EMIT_MIN_VERSION_DEFAULT,
                                 SENDME_EMIT_MIN_VERSION_MIN,
                                 SENDME_EMIT_MIN_VERSION_MAX);
}

/* Return the minimum version given by the consensus (if any) that should be
 * accepted when receiving a SENDME cell. */
STATIC int
get_accept_min_version(void)
{
  return networkstatus_get_param(NULL, "sendme_accept_min_version",
                                 SENDME_ACCEPT_MIN_VERSION_DEFAULT,
                                 SENDME_ACCEPT_MIN_VERSION_MIN,
                                 SENDME_ACCEPT_MIN_VERSION_MAX);
}

/* Pop the first cell digset on the given circuit from the SENDME last digests
 * list. NULL is returned if the list is uninitialized or empty.
 *
 * The caller gets ownership of the returned digest thus is responsible for
 * freeing the memory. */
static uint8_t *
pop_first_cell_digest(const circuit_t *circ)
{
  uint8_t *circ_digest;

  tor_assert(circ);

  if (circ->sendme_last_digests == NULL ||
      smartlist_len(circ->sendme_last_digests) == 0) {
    return NULL;
  }

  circ_digest = smartlist_get(circ->sendme_last_digests, 0);
  smartlist_del_keeporder(circ->sendme_last_digests, 0);
  return circ_digest;
}

/* Return true iff the given cell tag matches the first digest in the
 * circuit sendme list. */
static bool
v1_tag_matches(const uint8_t *circ_digest,
               const uint8_t *cell_tag, size_t tag_len)
{
  tor_assert(circ_digest);
  tor_assert(cell_tag);

  /* Compare the digest with the one in the SENDME. This cell is invalid
   * without a perfect match. */
  if (tor_memneq(circ_digest, cell_tag, tag_len)) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "SENDME v1 cell digest do not match.");
    return false;
  }

  /* Digests matches! */
  return true;
}

/* Return true iff the given decoded SENDME version 1 cell is valid and
 * matches the expected digest on the circuit.
 *
 * Validation is done by comparing the digest in the cell from the previous
 * cell we saw which tells us that the other side has in fact seen that cell.
 * See proposal 289 for more details. */
static bool
cell_v1_is_valid(const sendme_cell_t *cell, const uint8_t *circ_digest,
                 size_t circ_digest_len)
{
  tor_assert(cell);
  tor_assert(circ_digest);

  size_t tag_len = sendme_cell_get_data_len(cell);
  if (! tag_len_ok(tag_len))
    return false;
  if (sendme_cell_getlen_data_v1_digest(cell) < tag_len)
    return false;
  if (tag_len != circ_digest_len)
    return false;

  const uint8_t *cell_digest = sendme_cell_getconstarray_data_v1_digest(cell);
  return v1_tag_matches(circ_digest, cell_digest, tag_len);
}

/* Return true iff the given cell version can be handled or if the minimum
 * accepted version from the consensus is known to us. */
STATIC bool
cell_version_can_be_handled(uint8_t cell_version)
{
  int accept_version = get_accept_min_version();

  /* We will first check if the consensus minimum accepted version can be
   * handled by us and if not, regardless of the cell version we got, we can't
   * continue. */
  if (accept_version > SENDME_MAX_SUPPORTED_VERSION) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Unable to accept SENDME version %u (from consensus). "
           "We only support <= %u. Probably your tor is too old?",
           accept_version, SENDME_MAX_SUPPORTED_VERSION);
    goto invalid;
  }

  /* Then, is this version below the accepted version from the consensus? If
   * yes, we must not handle it. */
  if (cell_version < accept_version) {
    log_info(LD_PROTOCOL, "Unacceptable SENDME version %u. Only "
                          "accepting %u (from consensus). Closing circuit.",
             cell_version, accept_version);
    goto invalid;
  }

  /* Is this cell version supported by us? */
  if (cell_version > SENDME_MAX_SUPPORTED_VERSION) {
    log_info(LD_PROTOCOL, "SENDME cell version %u is not supported by us. "
                          "We only support <= %u",
             cell_version, SENDME_MAX_SUPPORTED_VERSION);
    goto invalid;
  }

  return true;
 invalid:
  return false;
}

/* Return true iff the encoded SENDME cell in cell_payload of length
 * cell_payload_len is valid. For each version:
 *
 *  0: No validation
 *  1: Authenticated with last cell digest.
 *
 * This is the main critical function to make sure we can continue to
 * send/recv cells on a circuit. If the SENDME is invalid, the circuit should
 * be marked for close by the caller. */
/*
 * NOTE: This function uses `layer_hint` to determine
 * what the sendme tag length will be, and nothing else.
 * Notably, we _don't_ keep a separate queue
 * of expected tags for each layer!
 */
STATIC bool
sendme_is_valid(const circuit_t *circ,
                const crypt_path_t *layer_hint,
                const uint8_t *cell_payload,
                size_t cell_payload_len)
{
  uint8_t cell_version;
  uint8_t *circ_digest = NULL;
  sendme_cell_t *cell = NULL;

  tor_assert(circ);
  tor_assert(cell_payload);

  /* An empty payload means version 0 so skip trunnel parsing. We won't be
   * able to parse a 0 length buffer into a valid SENDME cell. */
  if (cell_payload_len == 0) {
    cell_version = 0;
  } else {
    /* First we'll decode the cell so we can get the version. */
    if (sendme_cell_parse(&cell, cell_payload, cell_payload_len) < 0) {
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
             "Unparseable SENDME cell received. Closing circuit.");
      goto invalid;
    }
    cell_version = sendme_cell_get_version(cell);
  }

  /* Validate that we can handle this cell version. */
  if (!cell_version_can_be_handled(cell_version)) {
    goto invalid;
  }

  /* Determine the expected tag length for this sendme. */
  size_t circ_expects_tag_len;
  if (layer_hint) {
    circ_expects_tag_len =
      relay_crypto_sendme_tag_len(&layer_hint->pvt_crypto);
  } else if (CIRCUIT_IS_ORCIRC(circ)) {
    const or_circuit_t *or_circ = CONST_TO_OR_CIRCUIT(circ);
    circ_expects_tag_len = relay_crypto_sendme_tag_len(&or_circ->crypto);
  } else {
    tor_assert_nonfatal_unreached();
    goto invalid;
  }

  /* Pop the first element that was added (FIFO). We do that regardless of the
   * version so we don't accumulate on the circuit if v0 is used by the other
   * end point. */
  circ_digest = pop_first_cell_digest(circ);
  if (circ_digest == NULL) {
    /* We shouldn't have received a SENDME if we have no digests. Log at
     * protocol warning because it can be tricked by sending many SENDMEs
     * without prior data cell. */
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "We received a SENDME but we have no cell digests to match. "
           "Closing circuit.");
    goto invalid;
  }  /* Validate depending on the version now. */
  switch (cell_version) {
  case 0x01:
    if (!cell_v1_is_valid(cell, circ_digest, circ_expects_tag_len)) {
      goto invalid;
    }
    break;
  case 0x00:
    /* Version 0, there is no work to be done on the payload so it is
     * necessarily valid if we pass the version validation. */
    break;
  default:
    log_warn(LD_PROTOCOL, "Unknown SENDME cell version %d received.",
             cell_version);
    tor_assert_nonfatal_unreached();
    break;
  }

  /* Valid cell. */
  sendme_cell_free(cell);
  tor_free(circ_digest);
  return true;
 invalid:
  sendme_cell_free(cell);
  tor_free(circ_digest);
  return false;
}

/* Build and encode a version 1 SENDME cell into payload, which must be at
 * least of RELAY_PAYLOAD_SIZE_MAX bytes, using the digest for the cell data.
 *
 * Return the size in bytes of the encoded cell in payload. A negative value
 * is returned on encoding failure. */
STATIC ssize_t
build_cell_payload_v1(const uint8_t *cell_tag, const size_t tag_len,
                      uint8_t *payload)
{
  ssize_t len = -1;
  sendme_cell_t *cell = NULL;

  tor_assert(cell_tag);
  tor_assert(tag_len_ok(tag_len));
  tor_assert(payload);

  cell = sendme_cell_new();

  /* Building a payload for version 1. */
  sendme_cell_set_version(cell, 0x01);
  /* Set the data length field for v1. */
  sendme_cell_set_data_len(cell, tag_len);
  sendme_cell_setlen_data_v1_digest(cell, tag_len);

  /* Copy the digest into the data payload. */
  memcpy(sendme_cell_getarray_data_v1_digest(cell), cell_tag, tag_len);

  /* Finally, encode the cell into the payload. */
  len = sendme_cell_encode(payload, RELAY_PAYLOAD_SIZE_MAX, cell);

  sendme_cell_free(cell);
  return len;
}

/* Send a circuit-level SENDME on the given circuit using the layer_hint if
 * not NULL. The digest is only used for version 1.
 *
 * Return 0 on success else a negative value and the circuit will be closed
 * because we failed to send the cell on it. */
static int
send_circuit_level_sendme(circuit_t *circ, crypt_path_t *layer_hint,
                          const uint8_t *cell_tag, size_t tag_len)
{
  uint8_t emit_version;
  uint8_t payload[RELAY_PAYLOAD_SIZE_MAX];
  ssize_t payload_len;

  tor_assert(circ);
  tor_assert(cell_tag);

  emit_version = get_emit_min_version();
  if (getenv("TOR_SENDME_V0_TEST") != NULL) {
    emit_version = 0;
    log_notice(LD_PROTOCOL, "SENDME_V0_TEST emitting version 0 cell");
  }
  switch (emit_version) {
  case 0x01:
    payload_len = build_cell_payload_v1(cell_tag, tag_len, payload);
    if (BUG(payload_len < 0)) {
      /* Unable to encode the cell, abort. We can recover from this by closing
       * the circuit but in theory it should never happen. */
      return -1;
    }
    log_debug(LD_PROTOCOL, "Emitting SENDME version 1 cell.");
    break;
  case 0x00:
    FALLTHROUGH;
  default:
    /* Unknown version, fallback to version 0 meaning no payload. */
    payload_len = 0;
    log_debug(LD_PROTOCOL, "Emitting SENDME version 0 cell. "
                           "Consensus emit version is %d", emit_version);
    break;
  }

  if (relay_send_command_from_edge(0, circ, RELAY_COMMAND_SENDME,
                                   (char *) payload, payload_len,
                                   layer_hint) < 0) {
    log_warn(LD_CIRC,
             "SENDME relay_send_command_from_edge failed. Circuit's closed.");
    return -1; /* the circuit's closed, don't continue */
  }
  return 0;
}

static bool
predictive_sendme_try_early(circuit_t *circ,
                            crypt_path_t *layer_hint,
                            int sendme_inc)
{
  predictive_sendme_state_t *state = get_predictive_sendme_state();
  const int deliver_window = layer_hint ? layer_hint->deliver_window :
                                          circ->deliver_window;
  const size_t payload_len =
    relay_cell_max_payload_size(RELAY_CELL_FORMAT_V0, RELAY_COMMAND_DATA);
  uint8_t predicted_tag[SENDME_TAG_LEN_TOR1];

  if (state == NULL || !state->synced || state->prediction_pending ||
      state->circuit != circ || state->layer_hint != layer_hint ||
      layer_hint == NULL || layer_hint->pvt_crypto.kind != RCK_TOR1 ||
      get_emit_min_version() != 1 ||
      deliver_window != CIRCWINDOW_START - sendme_inc +
                        PREDICTIVE_SENDME_ADVANCE_CELLS ||
      state->predictable_cells < PREDICTIVE_SENDME_ADVANCE_CELLS ||
      state->next_file_offset > state->file->size ||
      payload_len * PREDICTIVE_SENDME_ADVANCE_CELLS >
        state->file->size - state->next_file_offset) {
    return false;
  }

  if (!predict_v0_data_tag(layer_hint->pvt_crypto.c.tor1.b_digest,
                           state->stream_id,
                           (const uint8_t *) state->file->data +
                             state->next_file_offset,
                           state->file->size - state->next_file_offset,
                           PREDICTIVE_SENDME_ADVANCE_CELLS,
                           predicted_tag)) {
    disable_predictive_sendme(state, "future tag calculation failed");
    return false;
  }

  if (send_circuit_level_sendme(circ, layer_hint, predicted_tag,
                                sizeof(predicted_tag)) < 0) {
    return false;
  }
  state->prediction_pending = true;
  log_notice(LD_PROTOCOL, "Predictive SENDME sent %d cells early; "
                          "deliver_window=%d safe_cells=%u",
             PREDICTIVE_SENDME_ADVANCE_CELLS, deliver_window,
             state->predictable_cells);
  return true;
}

/* Record the sendme tag as expected in a future SENDME, */
static void
record_cell_digest_on_circ(circuit_t *circ,
                           const uint8_t *sendme_tag,
                           size_t tag_len)
{
  tor_assert(circ);
  tor_assert(sendme_tag);

  /* Add the digest to the last seen list in the circuit. */
  if (circ->sendme_last_digests == NULL) {
    circ->sendme_last_digests = smartlist_new();
  }
  // We always allocate the largest possible tag here to
  // make sure we don't have heap overflow bugs.
  uint8_t *tag;
  if (tag_len == SENDME_TAG_LEN_CGO) {
    tag = tor_malloc_zero(SENDME_TAG_LEN_TOR1);
    memcpy(tag, sendme_tag, tag_len);
    // (The final bytes were initialized to zero.)
  } else if (tag_len == SENDME_TAG_LEN_TOR1) {
    tag = tor_memdup(sendme_tag, SENDME_TAG_LEN_TOR1);
  } else {
    tor_assert_unreached();
  }

  smartlist_add(circ->sendme_last_digests, tag);
}

/*
 * Public API
 */

/** Called when we've just received a relay data cell, when we've just
 * finished flushing all bytes to stream <b>conn</b>, or when we've flushed
 * *some* bytes to the stream <b>conn</b>.
 *
 * If conn->outbuf is not too full, and our deliver window is low, send back a
 * suitable number of stream-level sendme cells.
 */
void
sendme_connection_edge_consider_sending(edge_connection_t *conn)
{
  tor_assert(conn);

  int log_domain = TO_CONN(conn)->type == CONN_TYPE_AP ? LD_APP : LD_EXIT;

  /* If we use flow control, we do not send stream sendmes */
  if (edge_uses_flow_control(conn))
    goto end;

  /* Don't send it if we still have data to deliver. */
  if (connection_outbuf_too_full(TO_CONN(conn))) {
    goto end;
  }

  if (circuit_get_by_edge_conn(conn) == NULL) {
    /* This can legitimately happen if the destroy has already arrived and
     * torn down the circuit. */
    log_info(log_domain, "No circuit associated with edge connection. "
                         "Skipping sending SENDME.");
    goto end;
  }

  while (conn->deliver_window <=
         (STREAMWINDOW_START - STREAMWINDOW_INCREMENT)) {
    log_debug(log_domain, "Outbuf %" TOR_PRIuSZ ", queuing stream SENDME.",
              buf_datalen(TO_CONN(conn)->outbuf));
    conn->deliver_window += STREAMWINDOW_INCREMENT;
    if (connection_edge_send_command(conn, RELAY_COMMAND_SENDME,
                                     NULL, 0) < 0) {
      log_debug(LD_CIRC, "connection_edge_send_command failed while sending "
                         "a SENDME. Circuit probably closed, skipping.");
      goto end; /* The circuit's closed, don't continue */
    }
  }

 end:
  return;
}

/** Check if the deliver_window for circuit <b>circ</b> (at hop
 * <b>layer_hint</b> if it's defined) is low enough that we should
 * send a circuit-level sendme back down the circuit. If so, send
 * enough sendmes that the window would be overfull if we sent any
 * more.
 */
void
sendme_circuit_consider_sending(circuit_t *circ, crypt_path_t *layer_hint,
                                const relay_msg_t *msg)
{
  bool sent_one_sendme = false;
  const uint8_t *tag;
  size_t tag_len = 0;
  int sendme_inc = sendme_get_inc_count(circ, layer_hint);

  predictive_sendme_note_data(circ, layer_hint, msg);
  if (predictive_sendme_try_early(circ, layer_hint, sendme_inc)) {
    return;
  }

  while ((layer_hint ? layer_hint->deliver_window : circ->deliver_window) <=
          CIRCWINDOW_START - sendme_inc) {
    log_debug(LD_CIRC,"Queuing circuit sendme.");
    predictive_sendme_state_t *state = &predictive_sendme_state;
    if (state->prediction_pending &&
        state->circuit == circ && state->layer_hint == layer_hint) {
      if (layer_hint) {
        layer_hint->deliver_window += sendme_inc;
      } else {
        circ->deliver_window += sendme_inc;
      }
      state->prediction_pending = false;
      log_info(LD_PROTOCOL, "Predictive SENDME completed early window");
      continue;
    }
    if (layer_hint) {
      layer_hint->deliver_window += sendme_inc;
      tag = cpath_get_sendme_tag(layer_hint, &tag_len);
    } else {
      circ->deliver_window += sendme_inc;
      tag = relay_crypto_get_sendme_tag(&TO_OR_CIRCUIT(circ)->crypto,
                                        &tag_len);
    }
    if (send_circuit_level_sendme(circ, layer_hint, tag, tag_len) < 0) {
      return; /* The circuit's closed, don't continue */
    }
    /* Current implementation is not suppose to send multiple SENDME at once
     * because this means we would use the same relay crypto digest for each
     * SENDME leading to a mismatch on the other side and the circuit to
     * collapse. Scream loudly if it ever happens so we can address it. */
    tor_assert_nonfatal(!sent_one_sendme);
    sent_one_sendme = true;
  }
}

/* Process a circuit-level SENDME cell that we just received. The layer_hint,
 * if not NULL, is the Exit hop of the connection which means that we are a
 * client. In that case, circ must be an origin circuit. The cell_body_len is
 * the length of the SENDME cell payload (excluding the header). The
 * cell_payload is the payload.
 *
 * This function validates the SENDME's digest, and then dispatches to
 * the appropriate congestion control algorithm in use on the circuit.
 *
 * Return 0 on success (the SENDME is valid and the package window has
 * been updated properly).
 *
 * On error, a negative value is returned, which indicates that the
 * circuit must be closed using the value as the reason for it. */
int
sendme_process_circuit_level(crypt_path_t *layer_hint,
                             circuit_t *circ, const uint8_t *cell_payload,
                             uint16_t cell_payload_len)
{
  tor_assert(circ);
  tor_assert(cell_payload);
  congestion_control_t *cc;

  /* Validate the SENDME cell. Depending on the version, different validation
   * can be done. An invalid SENDME requires us to close the circuit. */
  if (!sendme_is_valid(circ, layer_hint, cell_payload, cell_payload_len)) {
    return -END_CIRC_REASON_TORPROTOCOL;
  }

  /* origin circuits need to count valid sendmes as valid protocol data */
  if (CIRCUIT_IS_ORIGIN(circ)) {
    circuit_read_valid_data(TO_ORIGIN_CIRCUIT(circ), cell_payload_len);
  }

  // Get CC
  if (layer_hint) {
    cc = layer_hint->ccontrol;
  } else {
    cc = circ->ccontrol;
  }

  /* If there is no CC object, assume fixed alg */
  if (!cc) {
    return sendme_process_circuit_level_impl(layer_hint, circ);
  }

  return congestion_control_dispatch_cc_alg(cc, circ);
}

/**
 * Process a SENDME for Tor's original fixed window circuit-level flow control.
 * Updates the package_window and ensures that it does not exceed the max.
 *
 * Returns -END_CIRC_REASON_TORPROTOCOL if the max is exceeded, otherwise
 * returns 0.
 */
int
sendme_process_circuit_level_impl(crypt_path_t *layer_hint, circuit_t *circ)
{
  /* If we are the origin of the circuit, we are the Client so we use the
   * layer hint (the Exit hop) for the package window tracking. */
  if (CIRCUIT_IS_ORIGIN(circ)) {
    /* If we are the origin of the circuit, it is impossible to not have a
     * cpath. Just in case, bug on it and close the circuit. */
    if (BUG(layer_hint == NULL)) {
      return -END_CIRC_REASON_TORPROTOCOL;
    }
    if ((layer_hint->package_window + CIRCWINDOW_INCREMENT) >
        CIRCWINDOW_START_MAX) {
      static struct ratelim_t exit_warn_ratelim = RATELIM_INIT(600);
      log_fn_ratelim(&exit_warn_ratelim, LOG_WARN, LD_PROTOCOL,
                     "Unexpected sendme cell from exit relay. "
                     "Closing circ.");
      return -END_CIRC_REASON_TORPROTOCOL;
    }
    layer_hint->package_window += CIRCWINDOW_INCREMENT;
    log_debug(LD_APP, "circ-level sendme at origin, packagewindow %d.",
              layer_hint->package_window);
  } else {
    /* We aren't the origin of this circuit so we are the Exit and thus we
     * track the package window with the circuit object. */
    if ((circ->package_window + CIRCWINDOW_INCREMENT) >
        CIRCWINDOW_START_MAX) {
      static struct ratelim_t client_warn_ratelim = RATELIM_INIT(600);
      log_fn_ratelim(&client_warn_ratelim, LOG_PROTOCOL_WARN, LD_PROTOCOL,
                     "Unexpected sendme cell from client. "
                     "Closing circ (window %d).", circ->package_window);
      return -END_CIRC_REASON_TORPROTOCOL;
    }
    circ->package_window += CIRCWINDOW_INCREMENT;
    log_debug(LD_EXIT, "circ-level sendme at non-origin, packagewindow %d.",
              circ->package_window);
  }

  return 0;
}

/* Process a stream-level SENDME cell that we just received. The conn is the
 * edge connection (stream) that the circuit circ is associated with. The
 * cell_body_len is the length of the payload (excluding the header).
 *
 * Return 0 on success (the SENDME is valid and the package window has
 * been updated properly).
 *
 * On error, a negative value is returned, which indicates that the
 * circuit must be closed using the value as the reason for it. */
int
sendme_process_stream_level(edge_connection_t *conn, circuit_t *circ,
                            uint16_t cell_body_len)
{
  tor_assert(conn);
  tor_assert(circ);

  if (edge_uses_flow_control(conn)) {
    log_fn(LOG_PROTOCOL_WARN, LD_EDGE,
           "Congestion control got stream sendme");
    return -END_CIRC_REASON_TORPROTOCOL;
  }

  /* Don't allow the other endpoint to request more than our maximum (i.e.
   * initial) stream SENDME window worth of data. Well-behaved stock clients
   * will not request more than this max (as per the check in the while loop
   * of sendme_connection_edge_consider_sending()). */
  if ((conn->package_window + STREAMWINDOW_INCREMENT) >
      STREAMWINDOW_START_MAX) {
    static struct ratelim_t stream_warn_ratelim = RATELIM_INIT(600);
    log_fn_ratelim(&stream_warn_ratelim, LOG_PROTOCOL_WARN, LD_PROTOCOL,
                   "Unexpected stream sendme cell. Closing circ (window %d).",
                   conn->package_window);
    return -END_CIRC_REASON_TORPROTOCOL;
  }
  /* At this point, the stream sendme is valid */
  conn->package_window += STREAMWINDOW_INCREMENT;

  /* We count circuit-level sendme's as valid delivered data because they are
   * rate limited. */
  if (CIRCUIT_IS_ORIGIN(circ)) {
    circuit_read_valid_data(TO_ORIGIN_CIRCUIT(circ), cell_body_len);
  }

  log_debug(CIRCUIT_IS_ORIGIN(circ) ? LD_APP : LD_EXIT,
            "stream-level sendme, package_window now %d.",
            conn->package_window);
  return 0;
}

/* Called when a relay DATA cell is received on the given circuit. If
 * layer_hint is NULL, this means we are the Exit end point else we are the
 * Client. Update the deliver window and return its new value. */
int
sendme_circuit_data_received(circuit_t *circ, crypt_path_t *layer_hint)
{
  int deliver_window, domain;

  if (CIRCUIT_IS_ORIGIN(circ)) {
    tor_assert(layer_hint);
    --layer_hint->deliver_window;
    deliver_window = layer_hint->deliver_window;
    domain = LD_APP;
  } else {
    tor_assert(!layer_hint);
    --circ->deliver_window;
    deliver_window = circ->deliver_window;
    domain = LD_EXIT;
  }

  log_debug(domain, "Circuit deliver_window now %d.", deliver_window);
  return deliver_window;
}

/* Called when a relay DATA cell is received for the given edge connection
 * conn. Update the deliver window and return its new value. */
int
sendme_stream_data_received(edge_connection_t *conn)
{
  tor_assert(conn);

  if (edge_uses_flow_control(conn)) {
    return flow_control_decide_xoff(conn);
  } else {
    return --conn->deliver_window;
  }
}

/* Called when a relay DATA cell is packaged on the given circuit. If
 * layer_hint is NULL, this means we are the Exit end point else we are the
 * Client. Update the package window and return its new value. */
int
sendme_note_circuit_data_packaged(circuit_t *circ, crypt_path_t *layer_hint)
{
  int package_window, domain;
  congestion_control_t *cc;

  tor_assert(circ);

  if (layer_hint) {
    cc = layer_hint->ccontrol;
    domain = LD_APP;
  } else {
    cc = circ->ccontrol;
    domain = LD_EXIT;
  }

  if (cc) {
    congestion_control_note_cell_sent(cc, circ, layer_hint);
  } else {
    /* Fixed alg uses package_window and must update it */

    if (CIRCUIT_IS_ORIGIN(circ)) {
      /* Client side. */
      tor_assert(layer_hint);
      --layer_hint->package_window;
      package_window = layer_hint->package_window;
    } else {
      /* Exit side. */
      tor_assert(!layer_hint);
      --circ->package_window;
      package_window = circ->package_window;
    }
    log_debug(domain, "Circuit package_window now %d.", package_window);
  }

  /* Return appropriate number designating how many cells can still be sent */
  return congestion_control_get_package_window(circ, layer_hint);
}

/* Called when a relay DATA cell is packaged for the given edge connection
 * conn. Update the package window and return its new value. */
int
sendme_note_stream_data_packaged(edge_connection_t *conn, size_t len)
{
  tor_assert(conn);

  if (edge_uses_flow_control(conn)) {
    flow_control_note_sent_data(conn, len);
    if (conn->xoff_received)
      return -1;
    else
      return 1;
  }

  --conn->package_window;
  log_debug(LD_APP, "Stream package_window now %d.", conn->package_window);
  return conn->package_window;
}

/* Record the cell digest into the circuit sendme digest list depending on
 * which edge we are. The digest is recorded only if we expect the next cell
 * that we will receive is a SENDME so we can match the digest. */
void
sendme_record_cell_digest_on_circ(circuit_t *circ, crypt_path_t *cpath)
{
  const uint8_t *sendme_tag;
  size_t tag_len = 0;

  tor_assert(circ);

  /* Is this the last cell before a SENDME? The idea is that if the
   * package_window reaches a multiple of the increment, after this cell, we
   * should expect a SENDME. */
  if (!circuit_sent_cell_for_sendme(circ, cpath)) {
    return;
  }

  /* Getting the digest is expensive so we only do it once we are certain to
   * record it on the circuit. */
  if (cpath) {
    sendme_tag = cpath_get_sendme_tag(cpath, &tag_len);
  } else {
    sendme_tag =
      relay_crypto_get_sendme_tag(&TO_OR_CIRCUIT(circ)->crypto, &tag_len);
  }

  record_cell_digest_on_circ(circ, sendme_tag, tag_len);
}
