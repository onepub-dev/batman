import 'package:dcli/dcli.dart';
import 'package:pci_file_monitor/src/parsed_args.dart';

void log(String message) {
  final args = ParsedArgs();

  if (args.colour == false) {
    message = Ansi.strip(message);
  }

  if (args.useLogfile) {
    args.logfile.append(message);
  } else {
    print(message);
  }
}

void logerr(String message) {
  final args = ParsedArgs();

  if (args.colour == false) {
    message = Ansi.strip(message);
  }

  if (args.useLogfile) {
    args.logfile.append(message);
  } else {
    printerr(message);
  }
}

void overwriteLine(String message) {
  final args = ParsedArgs();
  if (!args.quiet) {
    if (args.useLogfile) {
      log(message);
    } else {
      Terminal().overwriteLine(message);
    }
  }
}
