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

package com.company.samladdonreferenceproject.web.login;

import com.haulmont.addon.saml.entity.SamlConnection;
import com.haulmont.addon.saml.security.SamlSession;
import com.haulmont.addon.saml.security.config.SamlConfig;
import com.haulmont.addon.saml.service.SamlService;
import com.haulmont.addon.saml.web.security.saml.SamlSessionPrincipal;
import com.haulmont.cuba.core.global.DataManager;
import com.haulmont.cuba.core.global.LoadContext;
import com.haulmont.cuba.core.global.View;
import com.haulmont.cuba.core.sys.AppContext;
import com.haulmont.cuba.core.sys.SecurityContext;
import com.haulmont.cuba.gui.components.Label;
import com.haulmont.cuba.gui.components.LookupField;
import com.haulmont.cuba.gui.executors.BackgroundWorker;
import com.haulmont.cuba.gui.executors.UIAccessor;
import com.haulmont.cuba.security.app.TrustedClientService;
import com.haulmont.cuba.security.auth.Credentials;
import com.haulmont.cuba.security.entity.User;
import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.security.global.UserSession;
import com.haulmont.cuba.web.app.loginwindow.AppLoginWindow;
import com.haulmont.cuba.web.auth.WebAuthConfig;
import com.haulmont.cuba.web.security.ExternalUserCredentials;
import com.vaadin.server.*;
import org.apache.commons.collections4.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Inject;
import java.io.IOException;
import java.security.Principal;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * @author kuchmin
 */
public class ExtAppLoginWindow extends AppLoginWindow {

    private static final Logger log = LoggerFactory.getLogger(ExtAppLoginWindow.class);

    @Inject
    protected SamlService samlService;
    @Inject
    protected TrustedClientService trustedClientService;
    @Inject
    protected DataManager dataManager;
    @Inject
    protected BackgroundWorker backgroundWorker;

    @Inject
    protected SamlConfig samlConfig;
    @Inject
    protected WebAuthConfig webAuthConfig;

    @Inject
    protected Label ssoLookupFieldLabel;
    @Inject
    protected LookupField ssoLookupField;

    protected RequestHandler samlCallbackRequestHandler = this::handleSamlCallBackRequest;

    protected UIAccessor uiAccessor;

    @Override
    public void init(Map<String, Object> params) {
        super.init(params);

        uiAccessor = backgroundWorker.getUIAccessor();

        ssoLookupField.setOptionsList(getActiveConnections());
        ssoLookupFieldLabel.setVisible(!CollectionUtils.isEmpty(ssoLookupField.getOptionsList()));
        ssoLookupField.setVisible(!CollectionUtils.isEmpty(ssoLookupField.getOptionsList()));
        ssoLookupField.addValueChangeListener(e -> {
            if (e.getValue() != null) {
                SamlConnection connection = (SamlConnection) e.getValue();
                VaadinSession.getCurrent().getSession().setAttribute(SamlSessionPrincipal.SAML_CONNECTION_CODE, connection.getCode());
                Page.getCurrent().setLocation(samlConfig.getSamlLoginUrl());
            }
            ssoLookupField.setValue(null);
        });
    }

    @Override
    public void ready() {
        super.ready();

        VaadinSession.getCurrent().addRequestHandler(samlCallbackRequestHandler);
        try {
            samlCallbackRequestHandler.handleRequest(VaadinSession.getCurrent(), null, null);
        } catch (IOException e) {
            log.error("Failed to check SAML login", e);
        }
    }

    protected boolean handleSamlCallBackRequest(VaadinSession session, @Nullable VaadinRequest request,
                                                @Nullable VaadinResponse response) throws IOException {
        Principal principal = VaadinService.getCurrentRequest().getUserPrincipal();
        if (principal instanceof SamlSessionPrincipal) {
            final SamlSession samlSession = ((SamlSessionPrincipal) principal).getSamlSession();
            uiAccessor.accessSynchronously(() -> {
                try {
                    User user = samlService.getUser(samlSession);
                    ExternalUserCredentials credentials = new ExternalUserCredentials(user.getLogin());
                    doLogin(credentials);
                } catch (LoginException e) {
                    log.info("Login by SAML failed", e);

                    showLoginException(String.format(getMessage("errors.message.samlLoginFailed"), samlSession.getPrincipal()));
                } catch (Exception e) {
                    log.warn("Login by SAML failed. Internal error.", e);

                    showUnhandledExceptionOnLogin(e);
                }
            });
        }
        return false;
    }

    @Override
    protected void doLogin(Credentials credentials) throws LoginException {
        super.doLogin(credentials);

        VaadinSession.getCurrent().removeRequestHandler(samlCallbackRequestHandler);
    }

    protected List<SamlConnection> getActiveConnections() {
        UserSession systemSession;
        try {
            systemSession = trustedClientService.getSystemSession(webAuthConfig.getTrustedClientPassword());
        } catch (LoginException e) {
            log.error("Unable to obtain system session", e);
            return Collections.emptyList();
        }
        return AppContext.withSecurityContext(new SecurityContext(systemSession), () -> {
            List<SamlConnection> items = dataManager.loadList(LoadContext.create(SamlConnection.class)
                    .setQuery(new LoadContext.Query("select e from samladdon$SamlConnection e where e.active = true order by e.code"))
                    .setView(View.MINIMAL));
            return items;
        });
    }
}