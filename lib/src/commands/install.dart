import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import '../dcli/resources/generated/resource_registry.g.dart';

import '../log.dart';
import '../rules.dart';

class InstallCommand extends Command<void> {
  @override
  String get description => 'Configures pcifim.';

  @override
  String get name => 'install';

  @override
  void run() {
    Settings().setVerbose(enabled: globalResults!['verbose'] as bool);
    final pathToPciFim = dirname(Rules.pathToRules);
    if (!exists(pathToPciFim)) {
      createDir(pathToPciFim, recursive: true);
    }

    ResourceRegistry.resources[basename(Rules.pathToRules)]!
        .unpack(Rules.pathToRules);

    log(green('installation complete'));
    log("Run 'pcifim baseline' to set an initial baseline");
    log("Schedule 'pcifim scan' to run at least weekly.");
  }
}
