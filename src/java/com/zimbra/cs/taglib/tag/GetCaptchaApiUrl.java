/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2006, 2007, 2009, 2010, 2011, 2013, 2014, 2016 Synacor, Inc.
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

import java.io.IOException;

import javax.servlet.jsp.JspContext;
import javax.servlet.jsp.JspException;
import javax.servlet.jsp.JspTagException;
import javax.servlet.jsp.PageContext;

import com.zimbra.cs.account.Provisioning;

import com.zimbra.common.service.ServiceException;

public class GetCaptchaApiUrl extends ZimbraSimpleTag {

    private String mVarCaptchaApiUrl;
    
    /**
     * Signifies whether it is an admin proxy login ("View mail" login).
     * If set to true, it is an admin login. Hence, do not invoke the import data
     * request. If false, it is a normal user login, call import data request if
     * the importData param is set to true.
     */
    
    public void setVarCaptchaApiUrl(String varCaptchaApiUrl) { this.mVarCaptchaApiUrl = varCaptchaApiUrl; }
    

    @Override
    public void doTag() throws JspException, IOException {
        JspContext jctxt = getJspContext();
        try {
            PageContext pageContext = (PageContext) jctxt;
	
            String zimbraCaptchaApiUrl = Provisioning.getInstance().getConfig().getAttr(Provisioning.A_zimbraCaptchaApiUrl, "");

            if (mVarCaptchaApiUrl != null) {
               jctxt.setAttribute(mVarCaptchaApiUrl, zimbraCaptchaApiUrl, PageContext.REQUEST_SCOPE);
            }
        } catch (ServiceException e) {
            throw new JspTagException(e.getMessage(), e);
        }
    }
}
