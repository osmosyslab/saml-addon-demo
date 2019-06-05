/*
 * Copyright (c) 2008-2018 Haulmont.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.haulmont.demo.saml.core;

import com.haulmont.addon.saml.core.BaseSamlProcessor;
import com.haulmont.addon.saml.core.SamlProcessor;
import com.haulmont.addon.saml.entity.SamlConnection;
import com.haulmont.addon.saml.security.SamlSession;
import org.springframework.stereotype.Component;

/**
 * @author adiatullin
 */
@Component
public class SamlIdpSamlProcessor extends BaseSamlProcessor implements SamlProcessor {

    @Override
    public String getName() {
        return "samlidp.io";
    }

    @Override
    protected String getLoginAttributeName(SamlSession samlSession, SamlConnection connection) {
        return "urn:oid:2.5.4.42";
    }

    @Override
    protected String getEmailAddressAttributeName(SamlSession samlSession, SamlConnection connection) {
        return "urn:oid:0.9.2342.19200300.100.1.3";
    }

    @Override
    protected String getFirstNameAttributeName(SamlSession samlSession, SamlConnection connection) {
        return "urn:oid:2.5.4.4";
    }

    @Override
    protected String getLastNameAttributeName(SamlSession samlSession, SamlConnection connection) {
        return "urn:oid:1.3.6.1.4.1.5923.1.1.1.6";
    }
}
