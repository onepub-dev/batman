import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import '../dcli/resources/generated/resource_registry.g.dart';

import '../log.dart';
import '../rules.dart';

class InstallCommand extends Command<void> {
  @override
  String get description => 'Configures batman.';

  @override
  String get name => 'install';

  @override
  void run() {
    Settings().setVerbose(enabled: globalResults!['verbose'] as bool);
    final pathToBatman = dirname(Rules.pathToRules);
    if (!exists(pathToBatman)) {
      createDir(pathToBatman, recursive: true);
    }

    ResourceRegistry.resources[basename(Rules.pathToRules)]!
        .unpack(Rules.pathToRules);

    log(green('installation complete'));
    log("Run 'batman baseline' to set an initial baseline");
    log("Schedule 'batman scan' to run at least weekly.");
  }
}
