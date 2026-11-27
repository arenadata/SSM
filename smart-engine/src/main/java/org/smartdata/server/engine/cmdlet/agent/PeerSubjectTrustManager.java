/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.smartdata.server.engine.cmdlet.agent;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.regex.Pattern;

/**
 * Trust manager that, after the delegate has validated the peer certificate chain,
 * additionally checks that the subject DN (in RFC 2253 format) of the peer certificate
 * fully matches the allowed pattern.
 */
public class PeerSubjectTrustManager extends X509ExtendedTrustManager {
  private static final Logger LOG = LoggerFactory.getLogger(PeerSubjectTrustManager.class);

  private final X509TrustManager delegate;
  private final Pattern allowedSubjectPattern;

  public PeerSubjectTrustManager(X509TrustManager delegate, Pattern allowedSubjectPattern) {
    this.delegate = delegate;
    this.allowedSubjectPattern = allowedSubjectPattern;
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    delegate.checkClientTrusted(chain, authType);
    checkSubject(chain);
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    delegate.checkServerTrusted(chain, authType);
    checkSubject(chain);
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
      throws CertificateException {
    if (delegate instanceof X509ExtendedTrustManager) {
      ((X509ExtendedTrustManager) delegate).checkClientTrusted(chain, authType, socket);
    } else {
      delegate.checkClientTrusted(chain, authType);
    }
    checkSubject(chain);
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
      throws CertificateException {
    if (delegate instanceof X509ExtendedTrustManager) {
      ((X509ExtendedTrustManager) delegate).checkServerTrusted(chain, authType, socket);
    } else {
      delegate.checkServerTrusted(chain, authType);
    }
    checkSubject(chain);
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
      throws CertificateException {
    if (delegate instanceof X509ExtendedTrustManager) {
      ((X509ExtendedTrustManager) delegate).checkClientTrusted(chain, authType, engine);
    } else {
      delegate.checkClientTrusted(chain, authType);
    }
    checkSubject(chain);
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
      throws CertificateException {
    if (delegate instanceof X509ExtendedTrustManager) {
      ((X509ExtendedTrustManager) delegate).checkServerTrusted(chain, authType, engine);
    } else {
      delegate.checkServerTrusted(chain, authType);
    }
    checkSubject(chain);
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return delegate.getAcceptedIssuers();
  }

  private void checkSubject(X509Certificate[] chain) throws CertificateException {
    if (chain == null || chain.length == 0) {
      throw new CertificateException("Peer certificate chain is empty");
    }
    String subject = chain[0].getSubjectX500Principal().getName();
    if (!allowedSubjectPattern.matcher(subject).matches()) {
      LOG.warn("Rejected peer certificate with subject '{}', "
          + "it doesn't match the allowed pattern '{}'", subject, allowedSubjectPattern);
      throw new CertificateException("Peer certificate subject '" + subject
          + "' doesn't match the allowed pattern '" + allowedSubjectPattern + "'");
    }
  }
}
