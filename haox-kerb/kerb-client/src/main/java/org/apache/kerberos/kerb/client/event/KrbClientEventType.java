package org.apache.kerberos.kerb.client.event;

import org.apache.haox.event.EventType;

public enum KrbClientEventType implements EventType {
    TGT_INTENT,
    TGT_RESULT,
    TKT_INTENT,
    TKT_RESULT
}
