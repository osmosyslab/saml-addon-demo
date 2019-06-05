/*
 * Copyright (c) 2008-2019 Haulmont.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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
public class SsoCircleSamlProcessor extends BaseSamlProcessor implements SamlProcessor {
    @Override
    public String getName() {
        return "ssocircle.com";
    }

    @Override
    protected String getLoginAttributeName(SamlSession samlSession, SamlConnection connection) {
        return "UserID";
    }

    @Override
    protected String getEmailAddressAttributeName(SamlSession samlSession, SamlConnection connection) {
        return "EmailAddress";
    }

    @Override
    protected String getFirstNameAttributeName(SamlSession samlSession, SamlConnection connection) {
        return "FirstName";
    }

    @Override
    protected String getLastNameAttributeName(SamlSession samlSession, SamlConnection connection) {
        return "LastName";
    }
}
