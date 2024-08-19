##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HTTP::Kubernetes
  include Msf::Exploit::Remote::HTTP::Kubernetes::Enumeration

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kubernetes Service Enumeration',
        'Description' => %q{
          This module enumerates Kubernetes API to report services and check if the conditions are met to launch CVE-2020-8554.
        },
        'Author' => ['Hugo Delgado'],
        'License' => MSF_LICENSE,
        'Notes' => {
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [],
          'Stability' => [CRASH_SAFE]
        },
        'DefaultOptions' => {
          'SSL' => true,
        },
        'Actions' => [
          ['default', { 'Description' => 'Check if the conditions are met for MITM' }]
        ],
        'DefaultAction' => 'default',
        'Platform' => ['linux', 'unix']
      )
    )

    register_options(
      [
        Opt::RHOSTS(nil, false),
        Opt::RPORT(nil, false),
        Msf::OptInt.new('SESSION', [false, 'An optional session to use for configuration']),
        OptRegexp.new('HIGHLIGHT_NAME_PATTERN', [true, 'PCRE regex of resource names to highlight', 'externalIPs']),
        OptEnum.new('OUTPUT', [true, 'output format to use', 'table', ['table', 'json']])
      ]
    )  
  end

  def output_for(type)
    case type
    when 'table'
      Msf::Exploit::Remote::HTTP::Kubernetes::Output::Table.new(self, highlight_name_pattern: datastore['externalIPs'])
    when 'json'
      Msf::Exploit::Remote::HTTP::Kubernetes::Output::JSON.new(self)
    end
  end

  def run
    validate_configuration!

    @kubernetes_client = Msf::Exploit::Remote::HTTP::Kubernetes::Client.new({ http_client: self, token: api_token })
    @output = output_for(datastore['output'])

    begin
      enum_all_services
    rescue Msf::Exploit::Remote::HTTP::Kubernetes::Error::ApiError => e
      print_error(e.message)
    end
  end
end

