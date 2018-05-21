/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Synacor, Inc.
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
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Map;
import java.net.URL;
import java.nio.charset.Charset;
import java.net.URLEncoder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.jsp.JspContext;
import javax.servlet.jsp.JspException;
import javax.servlet.jsp.JspTagException;
import javax.servlet.jsp.PageContext;

import com.zimbra.client.ZAuthResult;
import com.zimbra.client.ZMailbox;
import com.zimbra.common.auth.ZAuthToken;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.HttpUtil;
import com.zimbra.common.util.WebSplitUtil;
import com.zimbra.common.util.ZimbraCookie;
import com.zimbra.common.util.ngxlookup.NginxAuthServer;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.taglib.ZJspSession;
import com.zimbra.cs.taglib.ngxlookup.NginxRouteLookUpConnector;
import com.zimbra.cs.account.AccountServiceException.AuthFailedServiceException;

import org.json.JSONObject;

public class LoginTag extends ZimbraSimpleTag {

    private String mUsername;
    private String mPassword;
    private String mNewPassword;
    private String mTwoFactorCode;
    private String mAuthToken;
    private boolean mAuthTokenInUrl;
    private boolean mRememberMe;
    private boolean mImportData;
    private boolean mAdminPreAuth;
    private String mUrl = null;
    private String mPath = null;
    private String mVarRedirectUrl = null;
    private String mVarAuthResult = null;
    private String mAttrs;
    private String mPrefs;
	private String mRequestedSkin;
    private boolean mCsrfTokenSecured;
    private boolean mTrustedDevice;
    private String mTrustedDeviceToken;
    private String mDeviceId;
    private boolean mGenerateDeviceId;

	public void setVarRedirectUrl(String varRedirectUrl) { this.mVarRedirectUrl = varRedirectUrl; }

    public void setVarAuthResult(String varAuthResult) { this.mVarAuthResult = varAuthResult; }

    public void setUsername(String username) { this.mUsername = username; }

    public void setPassword(String password) { this.mPassword = password; }

    public void setTwoFactorCode(String code) { this.mTwoFactorCode = code; }

    public void setNewpassword(String password) { this.mNewPassword = password; }

    public void setRememberme(boolean rememberMe) { this.mRememberMe = rememberMe; }

    public void setImportData(boolean importData) { this.mImportData = importData; }

    public void setCsrfTokenSecured(boolean csrfTokenSecured) { this.mCsrfTokenSecured = csrfTokenSecured; }

    /**
     * Signifies whether it is an admin proxy login ("View mail" login).
     * If set to true, it is an admin login. Hence, do not invoke the import data
     * request. If false, it is a normal user login, call import data request if
     * the importData param is set to true.
     */
    public void setAdminPreAuth(boolean isAdmin) { this.mAdminPreAuth = isAdmin; }

    public void setAuthtoken(String authToken) { this.mAuthToken = authToken; }

    public void setAuthtokenInUrl(boolean authTokenInUrl) { this.mAuthTokenInUrl = authTokenInUrl; }

    public void setUrl(String url) { this.mUrl = url; }

    public void setPrefs(String prefs) { this.mPrefs = prefs; }

    public void setAttrs(String attrs) { this.mAttrs = attrs; }

    public void setRequestedSkin(String skin) { this.mRequestedSkin = skin; }

    public void setTrustedDevice(Boolean trusted) { this.mTrustedDevice = trusted; }

    public void setTrustedDeviceToken(String token) { this.mTrustedDeviceToken = token; }

    public void setGenerateDeviceId(Boolean generateId) { this.mGenerateDeviceId = generateId; }

    public void setDeviceId(String deviceId) { this.mDeviceId = deviceId; }

    private String getVirtualHost(HttpServletRequest request) {
        return HttpUtil.getVirtualHost(request);
    }

    @Override
    public void doTag() throws JspException, IOException {
        JspContext jctxt = getJspContext();
        try {
            PageContext pageContext = (PageContext) jctxt;
            HttpServletRequest request = (HttpServletRequest) pageContext.getRequest();

            if (request.getParameter("captchaId") != null  && request.getParameter("captchaInput") != null && !isCaptchaValid(request.getParameter("captchaId"), request.getParameter("captchaInput"))) {
                throw AuthFailedServiceException.INVALID_CAPTCHA();
            }

            String serverName = request.getServerName();

            ZMailbox.Options options = new ZMailbox.Options();

            options.setClientIp(ZJspSession.getRemoteAddr(pageContext));

            options.setNoSession(true);

            if (mPrefs != null && mPrefs.length() > 0) {
                options.setPrefs(Arrays.asList(mPrefs.split(",")));
            }

            if (mAttrs != null && mAttrs.length() > 0) {
                options.setAttrs(Arrays.asList(mAttrs.split(",")));
            }

            if (mTwoFactorCode != null && mTwoFactorCode.length() > 0) {
                options.setTwoFactorCode(mTwoFactorCode);
            }

            if (mAuthToken != null) {
                options.setAuthToken(mAuthToken);
                options.setAuthAuthToken(true);
            } else {
                String virtualHost = getVirtualHost(request);
                boolean zimbraAuthDomainCheckEnabled = Provisioning.getInstance().getConfig().getBooleanAttr(Provisioning.A_zimbraAuthDomainCheckEnabled, false);

                if (zimbraAuthDomainCheckEnabled && mUsername != null && !mUsername.isEmpty() && mUsername.indexOf("@") != -1) {
                    String usernameSplit[]= mUsername.split("@");

                    // check if user domain matches current virtual host.
                    if (!virtualHost.equals(usernameSplit[1])) {
                        throw AuthFailedServiceException.AUTH_FAILED(mUsername, "", "Invalid username for host = ".concat(virtualHost));
                    }
                }
                options.setAccount(mUsername);
                options.setPassword(mPassword);
                options.setVirtualHost(virtualHost);
                if (mNewPassword != null && mNewPassword.length() > 0)
                    options.setNewPassword(mNewPassword);
            }

            if (mUrl == null) {
                if (mAuthToken == null && WebSplitUtil.isZimbraWebClientSplitEnabled()) {
                    String protocol = (ZJspSession.isProtocolModeHttps() ? "httpssl" : "http");
                    NginxAuthServer nginxLookUpServer = NginxRouteLookUpConnector.getClient().getRouteforAccount(mUsername, "username",
                            protocol, HttpUtil.getVirtualHost(request), request.getRemoteAddr(), request.getHeader("Virtual-Host"));
                    // In case of https, protocol needs to be https for the URL and not httpssl as passed to getRouteforAccount
                    protocol = (ZJspSession.isProtocolModeHttps() ? "https" : "http");
                    mUrl = protocol + "://" + nginxLookUpServer.getNginxAuthServer() + "/service/soap";
                } else {
                    mUrl = ZJspSession.getSoapURL(pageContext);
                }
            }
            options.setUri(mUrl);
            options.setRequestedSkin(mRequestedSkin);

            if (mCsrfTokenSecured) {
                options.setCsrfSupported(mCsrfTokenSecured);
            }
            if (mTrustedDevice) {
                options.setTrustedDevice(true);
            }
            if (mTrustedDeviceToken != null) {
                options.setTrustedDeviceToken(mTrustedDeviceToken);
            }
            if (mGenerateDeviceId) {
                options.setGenerateDeviceId(true);
            }
            if (mDeviceId != null) {
                options.setDeviceId(mDeviceId);
            }
            ZMailbox mbox = ZMailbox.getMailbox(options);
            HttpServletResponse response = (HttpServletResponse) pageContext.getResponse();

            String refer = mbox.getAuthResult().getRefer();
            boolean needRefer = (refer != null && !refer.equalsIgnoreCase(serverName));

            if ((mAuthToken == null || mAuthTokenInUrl || (mTwoFactorCode != null && mTwoFactorCode.length() > 0)) && !needRefer) {
                //Rewrite the ZM_AUTH_TOKEN cookie in case of successful two factor authentication
                setCookie(response,
                        mbox.getAuthToken(),
                        ZJspSession.secureAuthTokenCookie(request),
                        mRememberMe,
                        mbox.getAuthResult().getExpires());
            }

            ZAuthResult authResult = mbox.getAuthResult();
            if (authResult.getTrustedToken() != null) {
                setTrustedCookie(response,
                        authResult.getTrustedToken(),
                        authResult.getTrustLifetime(),
                        ZJspSession.secureAuthTokenCookie(request));
            }
            //if (!needRefer)
            //    ZJspSession.setSession((PageContext)jctxt, mbox);

            if (mVarRedirectUrl != null) {
                jctxt.setAttribute(mVarRedirectUrl,
                        ZJspSession.getPostLoginRedirectUrl(pageContext, mPath, mbox.getAuthResult(), mRememberMe, needRefer),
                        PageContext.REQUEST_SCOPE);
            }

            if (mVarAuthResult != null) {
                jctxt.setAttribute(mVarAuthResult, mbox.getAuthResult(), PageContext.REQUEST_SCOPE);
            }

            if (!authResult.getTwoFactorAuthRequired()) {
                //bug: 75754 invoking import data request only when zimbraDataSourceImportOnLogin is set
                boolean importDataOnLoginAttr = mbox.getFeatures().getDataSourceImportOnLogin();
                if (mImportData && !mAdminPreAuth && importDataOnLoginAttr) {
                    mbox.importData(mbox.getAllDataSources());
                }
            }

        } catch (ServiceException e) {
            throw new JspTagException(e.getMessage(), e);
        }
    }

    public static void setCookie(HttpServletResponse response, ZAuthToken zat,
            boolean secure, boolean rememberMe, long expires) {
        Map<String, String> cookieMap = zat.cookieMap(false);
        Integer maxAge = null;
        if (rememberMe) {
            long timeLeft = expires - System.currentTimeMillis();
            if (timeLeft > 0) {
                maxAge = new Integer((int)(timeLeft/1000));
            }
        } else {
            maxAge = new Integer(-1);
        }

        for (Map.Entry<String, String> ck : cookieMap.entrySet()) {
            ZimbraCookie.addHttpOnlyCookie(response, ck.getKey(), ck.getValue(),
                    ZimbraCookie.PATH_ROOT, maxAge, secure);
        }
    }

    public static void setTrustedCookie(HttpServletResponse response, String trustedToken, long expires, boolean secure) {
        Long timeLeft = expires - System.currentTimeMillis();
        String name = ZimbraCookie.COOKIE_ZM_TRUST_TOKEN;
        String path = ZimbraCookie.PATH_ROOT;
        Integer secondsLeft = Integer.valueOf((int)(timeLeft / 1000));
        if (timeLeft > 0) {
            ZimbraCookie.addHttpOnlyCookie(response, name, trustedToken, path, secondsLeft, secure);
        } else {
            ZimbraCookie.clearCookie(response, name);
        }
    }

    public static boolean isCaptchaValid(String captchaId, String captchaInput) {
        try {
            String zimbraCaptchaApiUrl = Provisioning.getInstance().getConfig().getAttr(Provisioning.A_zimbraCaptchaApiUrl, "");
            
            String url = zimbraCaptchaApiUrl + "/verifyCaptcha?"
                    + "captchaId=" + URLEncoder.encode(captchaId, "UTF-8")
                    + "&captchaInput=" + URLEncoder.encode(captchaInput, "UTF-8");
            InputStream res = new URL(url.trim()).openStream();
            BufferedReader rd = new BufferedReader(new InputStreamReader(res, Charset.forName("UTF-8")));

            StringBuilder sb = new StringBuilder();
            int cp;
            while ((cp = rd.read()) != -1) {
                sb.append((char) cp);
            }
            String response = sb.toString();
            res.close();
            
            if ("1".equals(response)) {
               return true;
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }
}
