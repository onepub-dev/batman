import 'package:dcli/dcli.dart';

import 'parsed_args.dart';

void run(List<String> args) {
  final parsed = ParsedArgs(args);

  Shell.current.releasePrivileges();

  parsed.run();
}
