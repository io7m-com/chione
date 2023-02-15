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


package com.io7m.chione;

import com.io7m.chione.internal.ChSecurityManager;
import com.io7m.chione.internal.ChServer;
import org.apache.activemq.artemis.api.core.QueueConfiguration;
import org.apache.activemq.artemis.api.core.RoutingType;
import org.apache.activemq.artemis.api.core.SimpleString;
import org.apache.activemq.artemis.core.config.CoreAddressConfiguration;
import org.apache.activemq.artemis.core.config.impl.ConfigurationImpl;
import org.apache.activemq.artemis.core.server.embedded.EmbeddedActiveMQ;
import org.apache.activemq.artemis.core.settings.impl.AddressFullMessagePolicy;
import org.apache.activemq.artemis.core.settings.impl.AddressSettings;
import org.apache.activemq.artemis.utils.critical.CriticalAnalyzerPolicy;

/**
 * A factory of servers.
 */

public final class ChServers
{
  /**
   * A factory of servers.
   */

  public ChServers()
  {

  }

  /**
   * Create a new server.
   *
   * @param configuration The server configuration
   *
   * @return A new server
   *
   * @throws Exception On errors
   */

  public ChServer createServer(
    final ChServerConfiguration configuration)
    throws Exception
  {
    final var artemis = new ConfigurationImpl();
    configureDirectories(configuration, artemis);
    configureAddresses(configuration, artemis);
    configureAcceptors(artemis);

    final var mq = new EmbeddedActiveMQ();
    mq.setSecurityManager(new ChSecurityManager(configuration));
    mq.setConfiguration(artemis);
    return new ChServer(mq);
  }

  private static void configureDirectories(
    final ChServerConfiguration configuration,
    final ConfigurationImpl artemis)
  {
    /*
     * Set all the directories.
     */

    final var base =
      configuration.dataDirectory()
        .toAbsolutePath();

    artemis.setJournalDirectory(base.resolve("journal").toString());
    artemis.setBindingsDirectory(base.resolve("bindings").toString());
    artemis.setLargeMessagesDirectory(base.resolve("large-messages").toString());
    artemis.setPagingDirectory(base.resolve("paging").toString());

    /*
     * Enable persistence.
     */

    artemis.setPersistenceEnabled(true);

    /*
     * Detect dead locks.
     */

    artemis.setCriticalAnalyzer(true);
    artemis.setCriticalAnalyzerPolicy(CriticalAnalyzerPolicy.HALT);
    artemis.setCriticalAnalyzerTimeout(120000L);
    artemis.setCriticalAnalyzerCheckPeriod(60000L);
  }

  private static void configureAcceptors(
    final ConfigurationImpl artemis)
    throws Exception
  {
    artemis.clearAcceptorConfigurations();
    artemis.addAcceptorConfiguration("all", "tcp://[::]:61000");
  }

  private static void configureAddresses(
    final ChServerConfiguration configuration,
    final ConfigurationImpl artemis)
  {
    for (final var address : configuration.addresses()) {
      final var c = new CoreAddressConfiguration();

      if (address instanceof ChAddressMulticast multicast) {
        c.addRoutingType(RoutingType.MULTICAST);
        c.setName(multicast.name());
      } else if (address instanceof ChAddressAnycast anycast) {
        final var q = new QueueConfiguration(anycast.queueName());
        c.addRoutingType(RoutingType.ANYCAST);
        c.setName(anycast.name());
        c.addQueueConfig(q);
      } else {
        throw new IllegalStateException();
      }

      artemis.addAddressConfiguration(c);
    }

    {
      final var c = new CoreAddressConfiguration();
      final var q = new QueueConfiguration("DeadLetterQueue");
      c.addRoutingType(RoutingType.ANYCAST);
      c.setName("DeadLetterQueue");
      c.addQueueConfig(q);
      artemis.addAddressConfiguration(c);
    }

    {
      final var c = new CoreAddressConfiguration();
      final var q = new QueueConfiguration("ExpiryQueue");
      c.addRoutingType(RoutingType.ANYCAST);
      c.setName("ExpiryQueue");
      c.addQueueConfig(q);
      artemis.addAddressConfiguration(c);
    }

    {
      final var settings = new AddressSettings();
      settings.setDeadLetterAddress(new SimpleString("DeadLetterQueue"));
      settings.setExpiryAddress(new SimpleString("ExpiryQueue"));
      settings.setRedeliveryDelay(0L);
      settings.setMaxSizeBytes(-1L);
      settings.setMessageCounterHistoryDayLimit(10);
      settings.setAddressFullMessagePolicy(AddressFullMessagePolicy.PAGE);
      settings.setAutoCreateAddresses(Boolean.TRUE);
      settings.setAutoCreateQueues(Boolean.TRUE);
      artemis.addAddressSetting("activemq.management#", settings);
    }

    {
      final var settings = new AddressSettings();
      settings.setDeadLetterAddress(new SimpleString("DeadLetterQueue"));
      settings.setExpiryAddress(new SimpleString("ExpiryQueue"));
      settings.setRedeliveryDelay(0L);
      settings.setMaxSizeBytes(-1L);
      settings.setMessageCounterHistoryDayLimit(10);
      settings.setAddressFullMessagePolicy(AddressFullMessagePolicy.PAGE);
      settings.setAutoCreateAddresses(Boolean.TRUE);
      settings.setAutoCreateQueues(Boolean.TRUE);
      artemis.addAddressSetting("#", settings);
    }
  }
}
