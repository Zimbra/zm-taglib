/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2023 Zimbra, Inc.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 * ***** END LICENSE BLOCK *****
 */
package com.zimbra.cs.taglib.tag;

import java.io.IOException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.jsp.JspContext;
import javax.servlet.jsp.JspException;
import javax.servlet.jsp.PageContext;

import com.zimbra.client.ZAuthResult;
import com.zimbra.common.auth.ZAuthToken;
import com.zimbra.common.soap.SoapHttpTransport;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.taglib.ZJspSession;
import com.zimbra.cs.taglib.bean.BeanUtils;

public class SendTFACodeTag extends ZimbraSimpleTag {

    private String mVarResult;
    private String mMethod;
    private ZAuthResult authResult;

    public void setVarResult(String varResult) { this.mVarResult = varResult; }
    public void setMethod(String method) { this.mMethod = method; }
    public void setAuthResult(ZAuthResult authResult) { this.authResult = authResult; }

    public void doTag() throws JspException, IOException {
        String action = "";
        try {
            JspContext jctxt = getJspContext();
            PageContext pageContext = (PageContext) jctxt;
            ZAuthToken zAuthToken;
            String authtoken;

            if (authResult != null) {
                // no authtoken is included in a http request just after login with username and password.
                // authtoken needs to be fetched from ZAuthResult
                zAuthToken = authResult.getAuthToken();
            } else {
                // ZAuthResult is empty when a TFA method is changed on login page.
                // check authtoken in a http request
                zAuthToken = ZJspSession.getAuthToken(pageContext);
            }

            if (!BeanUtils.isTFARequired(zAuthToken)) {
                throw new Exception("invalid authtoken was used to call SendTFACodeRequest");
            }

            if ("app".equals(mMethod)) {
                ZimbraLog.webclient.debug("SendTFACodeRequest with action=reset");
                action = "reset";
            } else if ("email".equals(mMethod)) {
                ZimbraLog.webclient.debug("SendTFACodeRequest with action=email");
                action = "email";
            } else {
                throw new Exception("unsupported method");
            }

            String soapUri = ZJspSession.getSoapURL(pageContext);
            authtoken = zAuthToken.getValue();

            HttpServletRequest request = (HttpServletRequest) pageContext.getRequest();
            Cookie[] cookies = request.getCookies();
            String csrfToken = "";
            for (Cookie cookie : cookies) {
                if ("ZM_LOGIN_CSRF".equals(cookie.getName())) {
                    csrfToken = cookie.getValue();
                    break;
                }
            }

            SoapHttpTransport transport = new SoapHttpTransport(soapUri);
            transport.setAuthToken(authtoken);
            transport.setCsrfToken(csrfToken);
            // TODO: replace SOAP request
            /*
            XMLElement req = new XMLElement(AccountConstants.XXXXX);
            Element resp = transport.invokeWithoutSession(req);
            */
            // TODO: check response and return succeeded or failed
            getJspContext().setAttribute(mVarResult, "succeeded");
        } catch (Exception e) {
            ZimbraLog.webclient.error("SendTFACodeRequest method=" + mMethod + " action=" + action + " failed.", e);
            getJspContext().setAttribute(mVarResult, "failed");
        }
    }
}
