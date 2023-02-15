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
import com.io7m.chione.passwords.ChPasswordAlgorithmPBKDF2HmacSHA256;
import com.io7m.claypot.core.CLPAbstractCommand;
import com.io7m.claypot.core.CLPCommandContextType;

import static com.io7m.claypot.core.CLPCommandType.Status.SUCCESS;

/**
 * Create a hashed password.
 */

@Parameters(commandDescription = "Create a hashed password.")
public final class ChCreateHashedPassword extends CLPAbstractCommand
{
  @Parameter(
    names = "--password",
    description = "The password text.",
    required = true
  )
  private String password;

  /**
   * Construct a command.
   *
   * @param inContext The command context
   */

  public ChCreateHashedPassword(
    final CLPCommandContextType inContext)
  {
    super(inContext);
  }

  @Override
  protected Status executeActual()
    throws Exception
  {
    final var algorithm =
      ChPasswordAlgorithmPBKDF2HmacSHA256.create(10000, 256);
    final var hashed =
      algorithm.createHashed(this.password);

    System.out.printf("""
                        <PasswordHashed Algorithm="%s"
                                        Salt="%s"
                                        Hash="%s"/>
                            """
                        .formatted(
                          algorithm.identifier(),
                          hashed.salt(),
                          hashed.hash()));
    return SUCCESS;
  }

  @Override
  public String name()
  {
    return "create-hashed-password";
  }
}
