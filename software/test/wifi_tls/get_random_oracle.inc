// VERBATIM from an earlier software/io/wifi/wifi.cc (not in this history), lines 482-591:
// GET_RANDOM before it moved into wifi_dedicated.cc. Do not edit; it is
// the oracle that the new code must match call for call (wifi_dedicated_test.cc).
// Checks a queued reply against the request, hands over its bytes if it is the
// answer, and frees it. A reply queued before the last reset of the buffer
// pool is dropped unread: the reset put its buffer back in the pool, where it
// may since have been handed to someone else. The scheduler stays suspended
// from that check until the buffer is freed, so that no reset, which only
// tasks do, can come in between. With check false the reply is only released.
static int take_random_reply(random_reply_t *reply, bool check, uint16_t sequence, uint8_t *buf, uint16_t len, uint8_t *source)
{
    int retval = WIFI_RANDOM_FOREIGN;
    int size = 0;
    int esp_err = 0;
    vTaskSuspendAll();
    if (reply->generation == esp32.uart->generation) {
        command_buf_t *packet = reply->buf;
        if (check) {
            size = packet->size;
            if (size >= (int)offsetof(rpc_get_random_resp, source)) {
                esp_err = ((rpc_get_random_resp *)packet->data)->esp_err;
            }
            retval = wifi_random_take_reply(packet->data, size, sequence, buf, len, source);
        }
        esp32.uart->FreeBuffer(packet); // does not block
    }
    xTaskResumeAll();
    if ((retval == WIFI_RANDOM_REFUSED) || (retval == WIFI_RANDOM_INVALID)) {
        if (size >= (int)offsetof(rpc_get_random_resp, source)) {
            printf("Get Random failed (%d). Size: %d. Error: %d.\n", retval, size, esp_err);
        } else {
            printf("Get Random failed (%d). Size: %d.\n", retval, size);
        }
    }
    return retval;
}

// A C64 program is waiting on the UCI for this one, so unlike the calls in
// wifi_cmd.cc it neither waits for the module forever nor trusts what comes
// back. Bytes are only handed out when the reply is the answer to this request
// and carries all of them. Between calls random_waiting is clear and
// random_replies is empty, so no reply is left to be taken for the next one.
int wifi_get_random(uint8_t *buf, uint16_t len, uint8_t *source)
{
    // Without the module application nothing can answer, so fail at once
    // rather than on a timeout.
    if ((wifi.getState() < eWifi_AppDetected) || !random_replies) {
        return WIFI_RANDOM_NO_MODULE;
    }
    // One request at a time: a second caller fails rather than waits.
    bool busy;
    ENTER_SAFE_SECTION;
    busy = random_waiting;
    random_waiting = true;
    LEAVE_SAFE_SECTION;
    if (busy) {
        return WIFI_RANDOM_BUSY;
    }

    int retval = WIFI_RANDOM_BUSY;
    uint16_t sequence = sequence_nr++;
    random_reply_t reply;
    command_buf_t *packet;
    if (esp32.uart->GetBuffer(&packet, 4) == pdFALSE) { // 20 ms
        printf(no_wifi_buf);
    } else {
        rpc_get_random_req *args = (rpc_get_random_req *)packet->data;
        args->hdr.command = CMD_GET_RANDOM;
        args->hdr.sequence = sequence;
        args->hdr.thread = WIFI_RANDOM_THREAD;
        args->length = len;
        packet->size = sizeof(rpc_get_random_req);

        if (esp32.uart->TransmitPacket(packet) == pdTRUE) {
            // The reply takes about a millisecond on the wire. It takes much
            // longer only while the module's single dispatcher is blocked, for
            // instance handing a scan or connect request to its connector task,
            // which can take seconds; that is worth a retry rather than a wait.
            // A late reply to an earlier request is skipped, within the same
            // 200 ms.
            const TickType_t timeout = 40; // 200 ms
            TickType_t start = xTaskGetTickCount();
            retval = WIFI_RANDOM_FOREIGN;
            while (retval == WIFI_RANDOM_FOREIGN) {
                TickType_t spent = xTaskGetTickCount() - start;
                if ((spent >= timeout) ||
                        (xQueueReceive(random_replies, &reply, timeout - spent) == pdFALSE)) {
                    retval = WIFI_RANDOM_BUSY;
                    break;
                }
                retval = take_random_reply(&reply, true, sequence, buf, len, source);
            }
        }
    }

    // Stop the interrupt from queueing replies, then release what it queued.
    // After a timeout that can still be our reply.
    random_waiting = false;
    while (xQueueReceive(random_replies, &reply, 0) == pdTRUE) {
        if (retval == WIFI_RANDOM_BUSY) {
            retval = take_random_reply(&reply, true, sequence, buf, len, source);
            if (retval == WIFI_RANDOM_FOREIGN) {
                retval = WIFI_RANDOM_BUSY;
            }
        } else {
            take_random_reply(&reply, false, 0, NULL, 0, NULL);
        }
    }
    if (retval == WIFI_RANDOM_BUSY) {
        printf("Get Random: no reply.\n");
    }
    return retval;
}
