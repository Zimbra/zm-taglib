/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2023 Synacor, Inc.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 * ***** END LICENSE BLOCK *****
 */
package com.zimbra.cs.taglib.tag;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.jsp.JspContext;
import javax.servlet.jsp.PageContext;

import com.zimbra.client.ZAuthResult;
import com.zimbra.common.account.ZAttrProvisioning;
import com.zimbra.common.util.StringUtil;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.soap.SoapProvisioning;
import com.zimbra.cs.taglib.bean.BeanUtils;
import com.zimbra.cs.taglib.bean.ZExceptionBean;

public class GetTFAConfigTag extends ZimbraSimpleTag {

    private ZAuthResult authResult;
    private ZExceptionBean exception;
    private String username;
    private String mVarTFAMethodAllowed;
    private String mVarTFAMethodEnabled;
    private String mVarMethod;
    private String mVarMaskedEmailAddress;
    private String mVarResetPasswordEnabled;

    private String defaultMethod = "app";
    private String[] defaultMethodOrder = new String[] { "app", "email" };

    public void setAuthResult(ZAuthResult authResult) { this.authResult = authResult; }

    public void setException(ZExceptionBean exception) { this.exception = exception; }

    public void setUsername(String username) { this.username = username; }

    public void setVarTFAMethodAllowed(String varTFAMethodAllowed) { this.mVarTFAMethodAllowed = varTFAMethodAllowed; }

    public void setVarTFAMethodEnabled(String varTFAMethodEnabled) { this.mVarTFAMethodEnabled = varTFAMethodEnabled; }

    public void setVarMethod(String varMethod) { this.mVarMethod = varMethod; }

    public void setVarMaskedEmailAddress(String varMaskedEmailAddress) { this.mVarMaskedEmailAddress = varMaskedEmailAddress; }

    public void setVarResetPasswordEnabled(String varResetPasswordEnabled) { this.mVarResetPasswordEnabled = varResetPasswordEnabled; }

    @Override
    public void doTag() {
        try {
            List<String> twoFactorAuthMethodAllowed;
            List<String> twoFactorAuthMethodEnabled;
            String primaryTwoFactorAuthMethod;
            String maskedPasswordRecoveryAddress;

            if (authResult != null) {
                twoFactorAuthMethodAllowed = authResult.getTwoFactorAuthMethodAllowed();
                twoFactorAuthMethodEnabled = authResult.getTwoFactorAuthMethodEnabled();
                primaryTwoFactorAuthMethod = authResult.getPrimaryTwoFactorAuthMethod();
                maskedPasswordRecoveryAddress = authResult.getMaskedPasswordRecoveryAddress();

                // backward compatibility
                if (twoFactorAuthMethodAllowed == null || twoFactorAuthMethodAllowed.size() == 0) {
                    twoFactorAuthMethodAllowed = Arrays.asList(defaultMethod);
                }
                if (authResult.getTwoFactorAuthRequired() && (twoFactorAuthMethodEnabled == null || twoFactorAuthMethodEnabled.size() == 0)) {
                    twoFactorAuthMethodEnabled = Arrays.asList(defaultMethod);
                }

                List<String> allowedAndEnabledMethodSorted = new ArrayList<String>();
                for (String method: defaultMethodOrder) {
                    if (twoFactorAuthMethodAllowed.contains(method) && twoFactorAuthMethodEnabled.contains(method)) {
                        if (method.equals("email") && StringUtil.isNullOrEmpty(maskedPasswordRecoveryAddress)) {
                            // email method is unavailable when no valid email has been set.
                            continue;
                        }
                        allowedAndEnabledMethodSorted.add(method);
                    }
                }
                getJspContext().setAttribute(mVarTFAMethodEnabled, String.join(",", allowedAndEnabledMethodSorted));

                if (!StringUtil.isNullOrEmpty(primaryTwoFactorAuthMethod) && allowedAndEnabledMethodSorted.contains(primaryTwoFactorAuthMethod)) {
                    getJspContext().setAttribute(mVarMethod, primaryTwoFactorAuthMethod);
                } else if (allowedAndEnabledMethodSorted.size() != 0) {
                    getJspContext().setAttribute(mVarMethod, allowedAndEnabledMethodSorted.get(0));
                }

                if (allowedAndEnabledMethodSorted.contains("email")) {
                    getJspContext().setAttribute(mVarMaskedEmailAddress, BeanUtils.cook(maskedPasswordRecoveryAddress));
                }
            } else if (exception != null && exception.getCode().equals("account.TWO_FACTOR_SETUP_REQUIRED")) {
                JspContext jctxt = getJspContext();
                PageContext pageContext = (PageContext) jctxt;
                SoapProvisioning sp = SoapProvisioning.getAdminInstance();
                Account account = sp.getAccount(username, true);
                String[] twoFactorAuthMethodAllowedStringArray = account.getTwoFactorAuthMethodAllowed();

                // backward compatibility
                if (twoFactorAuthMethodAllowedStringArray == null || twoFactorAuthMethodAllowedStringArray.length == 0) {
                    twoFactorAuthMethodAllowedStringArray = new String[]{ defaultMethod };
                }

                twoFactorAuthMethodAllowed = Arrays.asList(twoFactorAuthMethodAllowedStringArray);
                List<String> allowedMethodSorted = new ArrayList<String>();
                for (String method: defaultMethodOrder) {
                    if (twoFactorAuthMethodAllowed.contains(method)) {
                        allowedMethodSorted.add(method);
                    }
                }
                ZAttrProvisioning.FeatureResetPasswordStatus featureResetPasswordStatue = account.getFeatureResetPasswordStatus();
                ZAttrProvisioning.PrefPasswordRecoveryAddressStatus prefPasswordRecoveryAddressStatus = account.getPrefPasswordRecoveryAddressStatus();
                boolean isResetPasswordEnabled = (featureResetPasswordStatue != null && featureResetPasswordStatue.isEnabled() &&
                                                  prefPasswordRecoveryAddressStatus != null && prefPasswordRecoveryAddressStatus.isVerified());
                getJspContext().setAttribute(mVarTFAMethodAllowed, String.join(",", allowedMethodSorted));
                getJspContext().setAttribute(mVarResetPasswordEnabled, isResetPasswordEnabled);
            } else {
                throw new Exception("No valid authResult or exception was passed");
            }
        } catch (Exception e) {
            // TODO: do a right error handling so that a proper message is shown on UI
            ZimbraLog.webclient.error("error getting TFA config:", e);
        }
    }
}
