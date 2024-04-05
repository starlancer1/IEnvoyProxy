#
# Be sure to run `pod lib lint IPtProxy.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'IEnvoyProxy'
  s.version          = '2.0.0'
  s.summary          = 'Lyrebird/Obfs4proxy, Snowflake and V2Ray for iOS and macOS'

  s.description      = <<-DESC
    All contained libraries are written in Go, which
    is a little annoying to use on iOS and Android.
    This project encapsulates all the machinations to make it work and provides an
    easy to install binary including a wrapper around all.

    Problems solved in particular are:

    - One cannot compile `main` packages with `gomobile`. All libs are patched
      to avoid this.
    - All libs are gathered under one roof here, since you cannot have two
      `gomobile` frameworks as dependencies, as there are some common Go
      runtime functions exported, which will create a name clash.
    - Environment variable changes during runtime will not be recognized by
      `goptlib` when done from within Swift/Objective-C. Therefore, sensible
      values are hardcoded in the Go wrapper.
    - The ports where the libs will listen on are hardcoded, since communicating
      the used ports back to the app would be quite some work (e.g. trying to
      read it from STDOUT) for very little benefit.
    - All libs are patched to accept all configuration parameters
      directly.

    Contained transport versions:

    | Transport | Version |
    |-----------|--------:|
    | Lyrebird  |   0.2.0 |
    | Snowflake |   2.8.1 |
    | V2Ray     |  5.15.1 |

                       DESC

  s.homepage         = 'https://github.com/stevenmcdonald/IEnvoyProxy'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Benjamin Erhart' => 'berhart@netzarchitekten.com' }
  s.source           = { :git => 'https://github.com/stevenmcdonald/IEnvoyProxy.git', :tag => s.version.to_s }
  s.social_media_url = 'https://twitter.com/tladesignz'

  s.ios.deployment_target = '12.0'
  s.osx.deployment_target = '11'

  s.preserve_paths = 'build.sh', '*.patch', 'IEnvoyProxy/*'

  # This will only be executed once.
  s.prepare_command = './build.sh'

  # That's why this is also here, albeit it will be too late here.
  # You will need to re-run `pod update` to make the last line work.
  s.script_phase = {
    :name => 'Go build of IEnvoyProxy.xcframework',
    :execution_position => :before_compile,
    :script => 'sh "$PODS_TARGET_SRCROOT/build.sh"',
    :output_files => ['$(DERIVED_FILE_DIR)/IEnvoyProxy.xcframework'],
  }

  # This will only work, if `prepare_command` was successful, or if you
  # called `pod update` a second time after a build which will have triggered
  # the `script_phase`, or if you ran `build.sh` manually.
  s.vendored_frameworks = 'IEnvoyProxy.xcframework'

  s.libraries = 'resolv'

end
