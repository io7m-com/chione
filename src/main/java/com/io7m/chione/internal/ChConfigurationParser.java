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

import com.io7m.anethum.common.ParseStatus;
import com.io7m.chione.ChAddressAnycast;
import com.io7m.chione.ChAddressMulticast;
import com.io7m.chione.ChAddressRoleGrants;
import com.io7m.chione.ChAddressType;
import com.io7m.chione.ChRoleGrants;
import com.io7m.chione.ChServerConfiguration;
import com.io7m.chione.ChUser;
import com.io7m.chione.internal.jaxb.AccessControl;
import com.io7m.chione.internal.jaxb.AddressAnycastType;
import com.io7m.chione.internal.jaxb.AddressMulticastType;
import com.io7m.chione.internal.jaxb.Addresses;
import com.io7m.chione.internal.jaxb.Configuration;
import com.io7m.chione.internal.jaxb.PermissionType;
import com.io7m.chione.internal.jaxb.RoleReference;
import com.io7m.chione.internal.jaxb.Roles;
import com.io7m.chione.internal.jaxb.Users;
import com.io7m.chione.passwords.ChPassword;
import com.io7m.chione.passwords.ChPasswordAlgorithms;
import com.io7m.chione.passwords.ChPasswordException;
import com.io7m.jlexing.core.LexicalPosition;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.ValidationEventLocator;
import org.apache.activemq.artemis.core.security.CheckType;

import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.SchemaFactory;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.FileSystem;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static com.io7m.anethum.common.ParseSeverity.PARSE_ERROR;
import static com.io7m.anethum.common.ParseSeverity.PARSE_WARNING;
import static jakarta.xml.bind.ValidationEvent.ERROR;
import static jakarta.xml.bind.ValidationEvent.FATAL_ERROR;
import static jakarta.xml.bind.ValidationEvent.WARNING;

/**
 * A configuration file parser.
 */

public final class ChConfigurationParser
{
  private final FileSystem fileSystem;
  private final URI source;
  private final InputStream stream;
  private final Consumer<ParseStatus> statusConsumer;
  private final ArrayList<ParseStatus> statusValues;
  private boolean failed;

  /**
   * A configuration file parser.
   *
   * @param inFileSystem     The filesystem
   * @param inSource         The source
   * @param inStatusConsumer The status consumer
   * @param inStream         The stream
   */

  public ChConfigurationParser(
    final FileSystem inFileSystem,
    final URI inSource,
    final InputStream inStream,
    final Consumer<ParseStatus> inStatusConsumer)
  {
    this.fileSystem =
      Objects.requireNonNull(inFileSystem, "inFileSystem");
    this.source =
      Objects.requireNonNull(inSource, "source");
    this.stream =
      Objects.requireNonNull(inStream, "stream");
    this.statusConsumer =
      Objects.requireNonNull(inStatusConsumer, "statusConsumer");
    this.statusValues =
      new ArrayList<ParseStatus>();
  }

  /**
   * Parse a configuration file.
   *
   * @return The parsed configuration
   *
   * @throws Exception On errors
   */

  public ChServerConfiguration parse()
    throws Exception
  {
    this.failed = false;
    this.statusValues.clear();

    final var schemas =
      SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
    final var schema =
      schemas.newSchema(
        ChConfigurationParser.class.getResource(
          "/com/io7m/chione/configuration.xsd")
      );

    final var context =
      JAXBContext.newInstance(
        "com.io7m.chione.internal.jaxb");
    final var unmarshaller =
      context.createUnmarshaller();

    unmarshaller.setEventHandler(event -> {
      final var locator = event.getLocator();
      switch (event.getSeverity()) {
        case WARNING -> {
          this.publishWarning(
            "warn-xml",
            locatorLexical(locator),
            event.getMessage()
          );
        }
        case ERROR, FATAL_ERROR -> {
          this.publishError(
            "error-xml-validation",
            locatorLexical(locator),
            event.getMessage()
          );
        }
      }
      return true;
    });

    unmarshaller.setSchema(schema);

    final var streamSource =
      new StreamSource(this.stream, this.source.toString());

    final var raw = (Configuration) unmarshaller.unmarshal(streamSource);
    if (this.failed) {
      throw new ChInternalParseException();
    }
    return this.processConfiguration(raw);
  }

  private ChServerConfiguration processConfiguration(
    final Configuration configuration)
    throws ChPasswordException
  {
    final var addresses =
      processAddresses(configuration.getAddresses());
    final var users =
      processUsers(configuration.getUsers());
    final var roles =
      processRoles(configuration.getRoles());
    final var accessControl =
      processAccessControl(configuration.getAccessControl());

    return new ChServerConfiguration(
      configuration.getName(),
      this.fileSystem.getPath(configuration.getDataDirectory()),
      addresses,
      roles,
      users,
      accessControl
    );
  }

  private static final class RoleContext
  {
    private final HashMap<String, HashMap<String, HashSet<CheckType>>> data;

    RoleContext()
    {
      this.data = new HashMap<>();
    }

    void grant(
      final String prefix,
      final String name,
      final CheckType type)
    {
      HashMap<String, HashSet<CheckType>> rolesForPrefix = this.data.get(prefix);
      if (rolesForPrefix == null) {
        rolesForPrefix = new HashMap<>();
      }
      this.data.put(prefix, rolesForPrefix);

      HashSet<CheckType> permissionsForRole = rolesForPrefix.get(name);
      if (permissionsForRole == null) {
        permissionsForRole = new HashSet<>();
      }
      rolesForPrefix.put(name, permissionsForRole);
      permissionsForRole.add(type);
    }

    public Map<String, ChAddressRoleGrants> results()
    {
      final HashMap<String, ChAddressRoleGrants> results =
        new HashMap<>();

      for (final var prefixEntry : this.data.entrySet()) {
        final var prefix =
          prefixEntry.getKey();
        final var rolesForPrefix =
          prefixEntry.getValue();

        final var grantsForRole =
          new HashMap<String, ChRoleGrants>();

        for (final var rolesEntry : rolesForPrefix.entrySet()) {
          final var roleName =
            rolesEntry.getKey();
          final var rolePermissions =
            rolesEntry.getValue();
          final var grants =
            new ChRoleGrants(roleName, Set.copyOf(rolePermissions));

          grantsForRole.put(roleName, grants);
        }

        final var addressGrants =
          new ChAddressRoleGrants(prefix, Map.copyOf(grantsForRole));

        results.put(addressGrants.address(), addressGrants);
      }

      return Map.copyOf(results);
    }
  }

  private static Map<String, ChAddressRoleGrants> processAccessControl(
    final AccessControl accessControl)
  {
    final var roleContext = new RoleContext();
    for (final var matching : accessControl.getForAddressesStartingWith()) {
      final var prefix = matching.getPrefix();
      final var grants = matching.getGrantPermission();

      for (final var grant : grants) {
        final var type = checkTypeOf(grant.getType());
        for (final var role : grant.getRoleReference()) {
          roleContext.grant(prefix, role.getName(), type);
        }
      }
    }

    return roleContext.results();
  }

  private static CheckType checkTypeOf(
    final PermissionType type)
  {
    return switch (type) {
      case BROWSE -> CheckType.BROWSE;
      case CONSUME -> CheckType.CONSUME;
      case CREATE_ADDRESS -> CheckType.CREATE_ADDRESS;
      case CREATE_DURABLE_QUEUE -> CheckType.CREATE_DURABLE_QUEUE;
      case CREATE_NON_DURABLE_QUEUE -> CheckType.CREATE_NON_DURABLE_QUEUE;
      case DELETE_ADDRESS -> CheckType.DELETE_ADDRESS;
      case DELETE_DURABLE_QUEUE -> CheckType.DELETE_DURABLE_QUEUE;
      case DELETE_NON_DURABLE_QUEUE -> CheckType.DELETE_NON_DURABLE_QUEUE;
      case MANAGE -> CheckType.MANAGE;
      case SEND -> CheckType.SEND;
    };
  }

  private static Map<String, ChUser> processUsers(
    final Users users)
    throws ChPasswordException
  {
    final var results = new HashMap<String, ChUser>();
    for (final var user : users.getUser()) {
      final var hashed =
        user.getPasswordHashed();
      final var algorithm =
        ChPasswordAlgorithms.parse(hashed.getAlgorithm());
      final var hashText =
        hashed.getHash();
      final var saltText =
        hashed.getSalt();

      final var roles =
        user.getUserRoles()
          .getRoleReference()
          .stream()
          .map(RoleReference::getName)
          .collect(Collectors.toUnmodifiableSet());

      results.put(
        user.getName(),
        new ChUser(
          user.getName(),
          new ChPassword(algorithm, hashText, saltText),
          roles
        )
      );
    }

    return Map.copyOf(results);
  }

  private static Set<String> processRoles(
    final Roles roles)
  {
    final var results = new HashSet<String>();
    for (final var role : roles.getRole()) {
      results.add(role.getName());
    }
    return Set.copyOf(results);
  }

  private static Set<ChAddressType> processAddresses(
    final Addresses addresses)
  {
    final var results = new HashSet<ChAddressType>();
    for (final var address : addresses.getAddressMulticastOrAddressAnycast()) {
      if (address instanceof AddressMulticastType multicast) {
        results.add(new ChAddressMulticast(multicast.getName()));
      } else if (address instanceof AddressAnycastType anycast) {
        results.add(new ChAddressAnycast(
          anycast.getName(),
          anycast.getQueueName()));
      } else {
        throw new IllegalStateException();
      }
    }
    return Set.copyOf(results);
  }

  private void publishError(
    final ParseStatus status)
  {
    if (status.severity() == PARSE_ERROR) {
      this.failed = true;
    }

    this.statusValues.add(status);
    this.statusConsumer.accept(status);
  }

  private ChInternalParseException publishError(
    final String errorCode,
    final LexicalPosition<URI> lex,
    final String message)
  {
    this.publishError(createParseError(errorCode, lex, message));
    return new ChInternalParseException();
  }

  private void publishWarning(
    final String errorCode,
    final LexicalPosition<URI> lex,
    final String message)
  {
    final var status =
      ParseStatus.builder()
        .setErrorCode(errorCode)
        .setLexical(lex)
        .setSeverity(PARSE_WARNING)
        .setMessage(message)
        .build();

    this.statusValues.add(status);
    this.statusConsumer.accept(status);
  }

  private static ParseStatus createParseError(
    final String errorCode,
    final LexicalPosition<URI> lexical,
    final String message)
  {
    return ParseStatus.builder()
      .setSeverity(PARSE_ERROR)
      .setErrorCode(errorCode)
      .setLexical(lexical)
      .setMessage(message)
      .build();
  }

  private static LexicalPosition<URI> locatorLexical(
    final ValidationEventLocator locator)
  {
    try {
      return LexicalPosition.of(
        locator.getLineNumber(),
        locator.getColumnNumber(),
        Optional.of(locator.getURL().toURI())
      );
    } catch (final URISyntaxException e) {
      throw new IllegalStateException(e);
    }
  }
}
