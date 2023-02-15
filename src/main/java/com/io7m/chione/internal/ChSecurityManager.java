/*
 * Copyright © 2022 Mark Raynsford <code@io7m.com> https://www.io7m.com
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 * IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


package com.io7m.chione.internal;

import com.io7m.chione.ChServerConfiguration;
import com.io7m.chione.passwords.ChPasswordException;
import org.apache.activemq.artemis.core.security.CheckType;
import org.apache.activemq.artemis.core.security.Role;
import org.apache.activemq.artemis.spi.core.protocol.RemotingConnection;
import org.apache.activemq.artemis.spi.core.security.ActiveMQSecurityManager2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.Set;

/**
 * A strict security manager.
 */

public final class ChSecurityManager implements ActiveMQSecurityManager2
{
  private static final Logger LOG =
    LoggerFactory.getLogger(ChSecurityManager.class);

  private final ChServerConfiguration configuration;

  /**
   * A strict security manager.
   *
   * @param inConfiguration The configuration
   */

  public ChSecurityManager(
    final ChServerConfiguration inConfiguration)
  {
    this.configuration =
      Objects.requireNonNull(inConfiguration, "configuration");
  }

  @Override
  public boolean validateUser(
    final String user,
    final String password)
  {
    if (user == null) {
      return false;
    }

    final var userRecord =
      this.configuration.users()
        .get(user);

    if (userRecord == null) {
      return false;
    }

    final var passwordRecord =
      userRecord.password();

    try {
      return passwordRecord.check(password);
    } catch (final ChPasswordException e) {
      LOG.error("password exception: ", e);
      return false;
    }
  }

  @Override
  public boolean validateUserAndRole(
    final String user,
    final String password,
    final Set<Role> roles,
    final CheckType checkType)
  {
    return false;
  }

  @Override
  public boolean validateUser(
    final String user,
    final String password,
    final X509Certificate[] certificates)
  {
    return this.validateUser(user, password);
  }

  @Override
  public boolean validateUserAndRole(
    final String user,
    final String password,
    final Set<Role> roles,
    final CheckType checkType,
    final String address,
    final RemotingConnection connection)
  {
    if (!this.validateUser(user, password)) {
      return false;
    }

    final var userRecord =
      this.configuration.users()
        .get(user);

    final var userRoles =
      userRecord.roles();

    final var access = this.configuration.accessControl();
    for (final var accessEntry : access.entrySet()) {
      final var prefix = accessEntry.getKey();
      if (address.startsWith(prefix)) {
        final var roleGrants = accessEntry.getValue();
        for (final var grantEntry : roleGrants.entrySet()) {
          final var role = grantEntry.getKey();
          if (userRoles.contains(role)) {
            if (checkType == grantEntry.getValue()) {
              return true;
            }
          }
        }
      }
    }

    return false;
  }
}
