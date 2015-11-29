/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.kerby.kerberos.kerb.client.request;

import org.apache.kerby.KOption;
import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.type.base.AuthToken;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataType;

/**
 * Tgs request with an Access Token.
 */
public class TgsRequestWithToken extends ArmoredTgsRequest {

    public TgsRequestWithToken(KrbContext context) throws KrbException {
        super(context);

        setAllowedPreauth(PaDataType.TOKEN_REQUEST);
    }

    @Override
    public KOptions getPreauthOptions() {
        KOptions results = super.getPreauthOptions();
        KOptions krbOptions = getKrbOptions();

        results.add(krbOptions.getOption(KrbOption.USE_TOKEN));
        results.add(krbOptions.getOption(KrbOption.TOKEN_USER_AC_TOKEN));

        return results;
    }

    @Override
    public PrincipalName getClientPrincipal() {
        KOption acToken = getPreauthOptions().getOption(KrbOption.TOKEN_USER_AC_TOKEN);
        AuthToken authToken = (AuthToken) acToken.getValue();
        return new PrincipalName(authToken.getSubject());
    }
}
