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

import com.zimbra.common.auth.ZAuthToken;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.soap.AccountConstants;
import com.zimbra.common.soap.Element;
import com.zimbra.common.soap.Element.XMLElement;
import com.zimbra.common.soap.SoapHttpTransport;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.client.ZSoapProvisioning;
import com.zimbra.cs.taglib.bean.BeanUtils;
import com.zimbra.cs.taglib.ZJspSession;

public class SendTFACodeTag extends ZimbraSimpleTag {

    private String mVarResult;
    private String mMethod;

    public void setVarResult(String varResult) { this.mVarResult = varResult; }
    public void setMethod(String method) { this.mMethod = method; }

    public void doTag() throws JspException, IOException {
        String action = "";
        try {
            JspContext jctxt = getJspContext();
            PageContext pageContext = (PageContext) jctxt;
            if (!BeanUtils.isTFARequired(pageContext)) {
                throw new Exception("invalid authtoken was used to call SendTFACodeRequest");
            }

            if ("app".equals(mMethod)) {
                ZimbraLog.webclient.info("SendTFACodeRequest with action=reset");
                action = "reset";
            } else if ("email".equals(mMethod)) {
                ZimbraLog.webclient.info("SendTFACodeRequest with action=email");
                action = "email";
            } else {
                ZimbraLog.webclient.info("SendTFACodeRequest action is not defined for a method: ", mMethod);
                action = "undefined";
            }

            String soapUri = ZJspSession.getSoapURL(pageContext);
            String authtoken = ZJspSession.getAuthToken(pageContext).getValue();

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
