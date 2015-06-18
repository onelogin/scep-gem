module SCEP
  class JSCEPCli
    include SCEP::Loggable
    autoload :Request, 'scep/jscep_cli/request'

    BUNDLED_JSCEP_CLI_JAR_PATH = File.join(File.dirname(__FILE__), '..', '..', 'bin', 'jscepcli-1.0.jar')

    attr_accessor :jarfile

    attr_accessor :java_executable

    def initialize(java_executable = 'java', jarfile = BUNDLED_JSCEP_CLI_JAR_PATH)
      @jarfile = jarfile
      @java_executable = java_executable
    end

    # @param request [SCEP::JSCEPCli::Request] the request to forward
    def forward(request)
      logger.info "Making JSCEP CLI request to #{request.url}"
      cmd = "#{java_executable} -jar #{jarfile} #{request.to_cli_arguments}"
      logger.debug "Executing command: #{cmd}"
      system cmd
    end

  end
end
