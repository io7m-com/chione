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


package com.io7m.chione.internal.commands;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.io7m.anethum.common.ParseStatus;
import com.io7m.chione.ChServerConfiguration;
import com.io7m.chione.ChServers;
import com.io7m.chione.internal.ChConfigurationParser;
import com.io7m.claypot.core.CLPAbstractCommand;
import com.io7m.claypot.core.CLPCommandContextType;
import org.slf4j.Logger;

import java.nio.file.Files;
import java.nio.file.Path;

import static com.io7m.claypot.core.CLPCommandType.Status.FAILURE;
import static com.io7m.claypot.core.CLPCommandType.Status.SUCCESS;

/**
 * Run the server.
 */

@Parameters(commandDescription = "Run the server.")
public final class ChRunServer extends CLPAbstractCommand
{
  @Parameter(
    names = "--file",
    description = "The configuration file",
    required = true
  )
  private Path file;

  /**
   * Construct a command.
   *
   * @param inContext The command context
   */

  public ChRunServer(
    final CLPCommandContextType inContext)
  {
    super(inContext);
  }

  @Override
  protected Status executeActual()
    throws Exception
  {
    final var logger = this.logger();

    this.file = this.file.toAbsolutePath();

    final ChServerConfiguration configuration;
    try (var stream = Files.newInputStream(this.file)) {
      final var parser =
        new ChConfigurationParser(
          this.file.getFileSystem(),
          this.file.toUri(),
          stream,
          status -> logParseStatus(logger, status)
        );
      configuration = parser.parse();
    } catch (final Exception e) {
      logger.error("error: ", e);
      return FAILURE;
    }

    final var servers = new ChServers();
    try (var server = servers.createServer(configuration)) {
      server.start();
    }
    return SUCCESS;
  }

  private static void logParseStatus(
    final Logger logger,
    final ParseStatus status)
  {
    switch (status.severity()) {
      case PARSE_ERROR -> {
        logger.error(
          "{}:{}: {}",
          Integer.valueOf(status.lexical().line()),
          Integer.valueOf(status.lexical().column()),
          status.message()
        );
      }
      case PARSE_WARNING -> {
        logger.warn(
          "{}:{}: {}",
          Integer.valueOf(status.lexical().line()),
          Integer.valueOf(status.lexical().column()),
          status.message()
        );
      }
      case PARSE_INFO -> {
        logger.info(
          "{}:{}: {}",
          Integer.valueOf(status.lexical().line()),
          Integer.valueOf(status.lexical().column()),
          status.message()
        );
      }
    }
  }

  @Override
  public String name()
  {
    return "server";
  }
}
