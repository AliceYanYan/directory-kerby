package org.apache.kerberos.kerb.server.request;

import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerberos.kerb.server.KdcContext;
import org.apache.kerberos.kerb.spec.KerberosTime;
import org.apache.kerberos.kerb.spec.common.*;
import org.apache.kerberos.kerb.spec.kdc.*;
import org.apache.kerberos.kerb.spec.ticket.Ticket;
import org.apache.kerberos.kerb.spec.ticket.TicketFlag;

public class AsRequest extends KdcRequest {

    public AsRequest(AsReq asReq, KdcContext kdcContext) {
        super(asReq, kdcContext);
    }

    @Override
    protected void makeReply() throws KrbException {
        Ticket ticket = getTicket();

        AsRep reply = new AsRep();

        reply.setCname(getClientEntry().getPrincipal());
        reply.setCrealm(kdcContext.getServerRealm());
        reply.setTicket(ticket);

        EncKdcRepPart encKdcRepPart = makeEncKdcRepPart();
        reply.setEncPart(encKdcRepPart);

        EncryptionKey clientKey = getClientKey();
        EncryptedData encryptedData = EncryptionUtil.seal(encKdcRepPart,
                clientKey, KeyUsage.AS_REP_ENCPART);
        reply.setEncryptedEncPart(encryptedData);

        setReply(reply);
    }

    protected EncKdcRepPart makeEncKdcRepPart() {
        KdcReq request = getKdcReq();
        Ticket ticket = getTicket();

        EncKdcRepPart encKdcRepPart = new EncAsRepPart();

        //session key
        encKdcRepPart.setKey(ticket.getEncPart().getKey());

        LastReq lastReq = new LastReq();
        LastReqEntry entry = new LastReqEntry();
        entry.setLrType(LastReqType.THE_LAST_INITIAL);
        entry.setLrValue(new KerberosTime());
        lastReq.add(entry);
        encKdcRepPart.setLastReq(lastReq);

        encKdcRepPart.setNonce(request.getReqBody().getNonce());

        encKdcRepPart.setFlags(ticket.getEncPart().getFlags());
        encKdcRepPart.setAuthTime(ticket.getEncPart().getAuthTime());
        encKdcRepPart.setStartTime(ticket.getEncPart().getStartTime());
        encKdcRepPart.setEndTime(ticket.getEncPart().getEndTime());

        if (ticket.getEncPart().getFlags().isFlagSet(TicketFlag.RENEWABLE)) {
            encKdcRepPart.setRenewTill(ticket.getEncPart().getRenewtill());
        }

        encKdcRepPart.setSname(ticket.getSname());
        encKdcRepPart.setSrealm(ticket.getRealm());
        encKdcRepPart.setCaddr(ticket.getEncPart().getClientAddresses());

        return encKdcRepPart;
    }
}
