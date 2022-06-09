/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:dcli/dcli.dart';
import 'package:mailer/mailer.dart';
import 'package:mailer/smtp_server.dart';

import 'batman_settings.dart';
import 'log.dart';

// yes I know this is duplicated from node, but it needs to be here
// for the backup_service build to work

void main() {
  log('you cant run this!');
}

// ignore: avoid_classes_with_only_static_members
class Email {
  static void sendEmail(String subject, String body, String emailToAddress) {
    final rules = BatmanSettings.load();

    final emailServer = rules.emailServer;
    final emailPort = rules.emailPort;
    final emailFromAddress = rules.emailFromAddress;

    if (emailFromAddress.isEmpty) {
      throw EmailException(
          'You must configure the emailFromaddress in batman.yaml');
    }

    final smtpServer = SmtpServer(emailServer,
        port: emailPort, allowInsecure: true, ignoreBadCertificate: true);

    // Create our message.
    final message = Message()
      ..from = Address(emailFromAddress)
      ..recipients.add(emailToAddress)
      ..subject = subject
      ..text = body;
    //..html = "<h1>Test</h1>\n<p>Hey! Here's some HTML content</p>";

    try {
      final sendReport = waitForEx(send(message, smtpServer));
      log('Message sent: ${sendReport.toString()}');
    } on MailerException catch (e) {
      log('Message not sent. $e');
      for (final p in e.problems) {
        log('Problem: ${p.code}: ${p.msg}');
      }
    }
  }
}

class EmailException implements Exception {
  EmailException(this.message);
  String message;
}
