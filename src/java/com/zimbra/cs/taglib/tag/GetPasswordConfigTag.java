/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2025 Synacor, Inc.
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

import com.zimbra.client.ZAuthResult;
import com.zimbra.common.service.ServiceException;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.taglib.ZJspSession;
import com.zimbra.cs.taglib.bean.BeanUtils;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.jsp.JspContext;
import javax.servlet.jsp.JspException;
import javax.servlet.jsp.JspTagException;
import javax.servlet.jsp.PageContext;

public class GetPasswordConfigTag extends ZimbraSimpleTag {

    private String mVarConfig;

    private ZAuthResult mAuthResult;

    public void setVarConfig(String varConfig) {
        this.mVarConfig = varConfig;
    }

    public void setAuthResult(ZAuthResult authResult) {
        this.mAuthResult = authResult;
    }

    @Override
    public void doTag() throws JspException, IOException {
        JspContext jctxt = getJspContext();
        try {
            PageContext pageContext = (PageContext) jctxt;
            HttpServletRequest request = (HttpServletRequest) pageContext.getRequest();

            String authTokenString = null;
            Account account = null;
            if (mAuthResult != null) {
                authTokenString = mAuthResult.getAuthToken().getValue();
            } else {
                Cookie[] cookies = request.getCookies();
                for (Cookie c : cookies) {
                    if (c.getName().equals(ZJspSession.COOKIE_NAME)) {
                        authTokenString = c.getValue();
                        break;
                    }
                }
            }
            account = BeanUtils.getAccountFromAuthToken(authTokenString, true);
            if (!BeanUtils.isPasswordChangeRequired(authTokenString) || account == null) {
                throw ServiceException.FAILURE("Invalid authtoken for change password", null);
            }

            Map<String, Object> map = new HashMap<>();
            String[] attributes = BeanUtils.getPasswordConfigAttrs();

            for (String attr : attributes) {
                map.put(attr, account.getAttr(attr));
            }

            if (mVarConfig != null) {
                jctxt.setAttribute(mVarConfig, map, PageContext.REQUEST_SCOPE);
            }
        } catch (ServiceException e) {
            throw new JspTagException(e.getMessage(), e);
        }
    }
}
