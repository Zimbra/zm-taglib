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

import javax.servlet.jsp.JspContext;
import javax.servlet.jsp.JspException;
import javax.servlet.jsp.PageContext;

import com.zimbra.client.ZAuthResult;
import com.zimbra.common.auth.ZAuthToken;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.soap.AccountConstants;
import com.zimbra.common.soap.Element;
import com.zimbra.common.soap.Element.XMLElement;
import com.zimbra.common.soap.SoapHttpTransport;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.taglib.ZJspSession;
import com.zimbra.cs.taglib.bean.BeanUtils;
import com.zimbra.soap.account.message.SendTwoFactorAuthCodeRequest.SendTwoFactorAuthCodeAction;
import com.zimbra.soap.account.message.SendTwoFactorAuthCodeResponse.SendTwoFactorAuthCodeStatus;

public class SendTwoFactorAuthCodeTag extends ZimbraSimpleTag {

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

            if (!BeanUtils.isTwoFactorAuthRequired(zAuthToken)) {
                ZimbraLog.webclient.warn("Invalid authtoken was used to call SendTwoFactorAuthCodeRequest");
                getJspContext().setAttribute(mVarResult, "failed");
                return;
            }

            if (AccountConstants.E_TWO_FACTOR_METHOD_APP.equals(mMethod)) {
                action = SendTwoFactorAuthCodeAction.RESET.toString();
            } else if (AccountConstants.E_TWO_FACTOR_METHOD_EMAIL.equals(mMethod)) {
                action = SendTwoFactorAuthCodeAction.EMAIL.toString();
            } else {
                ZimbraLog.webclient.info("Configuration for two-factor authentication failed. Unsupported method: " + mMethod);
                getJspContext().setAttribute(mVarResult, "failed");
                return;
            }

            String soapUri = ZJspSession.getSoapURL(pageContext);
            authtoken = zAuthToken.getValue();

            SoapHttpTransport transport = new SoapHttpTransport(soapUri);
            transport.setAuthToken(authtoken);

            XMLElement req = new XMLElement(AccountConstants.E_SEND_TWO_FACTOR_AUTH_CODE_REQUEST);
            req.addAttribute(XMLElement.A_NAMESPACE, AccountConstants.NAMESPACE_STR);
            req.addUniqueElement(AccountConstants.E_ACTION).setText(action);

            ZimbraLog.webclient.debug("SendTwoFactorAuthCodeRequest with action=" + action + " and method=" + mMethod);
            Element resp = transport.invokeWithoutSession(req);
            String status = resp.getElement(AccountConstants.A_STATUS).getText();
            if ((AccountConstants.E_TWO_FACTOR_METHOD_APP.equals(mMethod) &&
                    SendTwoFactorAuthCodeStatus.RESET_FAILED.toString().equals(status)) ||
                (AccountConstants.E_TWO_FACTOR_METHOD_EMAIL.equals(mMethod) &&
                    SendTwoFactorAuthCodeStatus.NOT_SENT.toString().equals(status))) {
                ZimbraLog.webclient.warn("Configuration for two-factor authentication failed. method=" + mMethod + " action=" + action);
                getJspContext().setAttribute(mVarResult, "failed");
            } else {
                getJspContext().setAttribute(mVarResult, "succeeded");
            }
        } catch (ServiceException e) {
            ZimbraLog.webclient.warn("Two-factor authentication could not be executed.");
            getJspContext().setAttribute(mVarResult, "failed");
        }
    }
}
