/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2011, 2013, 2014, 2016 Synacor, Inc.
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
package com.zimbra.cs.taglib.tag.filter;

import com.zimbra.common.filter.Sieve;
import com.zimbra.common.service.ServiceException;
import com.zimbra.cs.taglib.tag.ZimbraSimpleTag;
import com.zimbra.client.ZFilterCondition.HeaderOp;
import com.zimbra.client.ZFilterCondition.ZAddressCondition;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.JspTagException;

public class AddressConditionTag extends ZimbraSimpleTag {
    private String mHeaderName;
    private Sieve.AddressPart mPart;
    private HeaderOp mOp;
    private String mValue;

    public void setValue(String value) { mValue = value; }
    public void setName(String name) { mHeaderName = name; }
    public void setOp(String op) throws ServiceException { mOp = HeaderOp.fromString(op); }
    public void setPart(String part) throws ServiceException {mPart = Sieve.AddressPart.fromString(part); }

    public void doTag() throws JspException {
        FilterRuleTag rule = (FilterRuleTag) findAncestorWithClass(this, FilterRuleTag.class);
        if (rule == null)
            throw new JspTagException("The addressCondition tag must be used within a filterRule tag");
        rule.addCondition(new ZAddressCondition(mHeaderName, mPart, mOp, mValue));
    }

}
