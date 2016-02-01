# encoding: utf-8
require "logstash/inputs/threadable"
require "logstash/namespace"
require "socket"
require "systemd/journal"
require "fileutils" # For touch

# Pull events from a local systemd journal.
#
# See requirements https://github.com/ledbettj/systemd-journal
class LogStash::Inputs::Journald < LogStash::Inputs::Threadable

    config_name "journald"

    # Where in the journal to start capturing logs
    # Options: head, tail
    config :seekto, :validate => [ "head", "tail" ], :default => "tail"

    # System journal flags
    # 0 = all avalable
    # 1 = local only
    # 2 = runtime only
    # 4 = system only
    #
    config :flags, :validate => [0, 1, 2, 4], :default => 0

    # Path to read journal files from
    #
    config :path, :validate => :string, :default => "/var/log/journal"

    # Filter on events. Not heavily tested.
    #
    config :filter, :validate => :hash, :required => false, :default => {}

    # Filter logs since the system booted (only relevant with seekto => "head")
    #
    config :thisboot, :validate => :boolean, :default => true

    # Lowercase annoying UPPERCASE fieldnames, remove underscore prefixes. (May clobber existing fields)
    #
    config :pretty_keys, :validate => :boolean, :default => false

    # Where to write the sincedb database (keeps track of the current
    # position of the journal). The default will write
    # the sincedb file to matching `$HOME/.sincedb_journal`
    #
    config :sincedb_path, :validate => :string

    # How often (in seconds) to write a since database with the current position of
    # the journal.
    #
    config :sincedb_write_interval, :validate => :number, :default => 15

    public
    def register
        opts = {
            flags: @flags,
            path: @path,
        }
        @hostname = Socket.gethostname
        @journal = Systemd::Journal.new(opts)
        @cursor = ""
        @written_cursor = ""
        @cursor_lock = Mutex.new
        $prettyfieldmap = {
            :MESSAGE => 'message',
            :MESSAGE_ID => 'message_id',
            :PRIORITY => 'priority',
            :CODE_FILE => 'code_file',
            :CODE_LINE => 'code_line',
            :CODE_FUNC => 'code_func',
            :ERRNO => 'errno',
            :SYSLOG_FACILITY => 'syslog_facility',
            :SYSLOG_IDENTIFIER => 'syslog_identifier',
            :SYSLOG_PID => 'syslog_pid',
            :_PID => 'pid',
            :_UID => 'uid',
            :_GID => 'gid',
            :_COMM => 'comm',
            :_EXE => 'exe',
            :_CMDLINE => 'cmdline',
            :_AUDIT_SESSION => 'audit_session',
            :_AUDIT_LOGINUID => 'audit_loginuid',
            :_SYSTEMD_CGROUP => 'systemd_cgroup',
            :_SYSTEMD_SESSION => 'systemd_session',
            :_SYSTEMD_UNIT => 'systemd_unit',
            :_SYSTEMD_USER_UNIT => 'systemd_user_unit',
            :_SYSTEMD_OWNER_UID => 'systemd_owner_uid',
            :_SELINUX_CONTEXT => 'selinux_context',
            :_SOURCE_REALTIME_TIMESTAMP => 'source_realtime_timestamp',
            :_BOOT_ID => 'boot_id',
            :_MACHINE_ID => 'machine_id',
            :_HOSTNAME => 'hostname',
            :_TRANSPORT => 'transport',
            :_KERNEL_DEVICE => 'kernel_device',
            :_KERNEL_SUBSYSTEM => 'kernel_subsystem',
            :_UDEV_SYSNAME => 'udev_sysname',
            :_UDEV_DEVNODE => 'udev_devnode',
            :_UDEV_DEVLINK => 'udev_devlink'
        }
        if @thisboot
            @filter[:_boot_id] = Systemd::Id128.boot_id
        end
        if @sincedb_path.nil?
            if ENV["SINCEDB_DIR"].nil? && ENV["HOME"].nil?
                @logger.error("No SINCEDB_DIR or HOME environment variable set, I don't know where " \
                              "to keep track of the files I'm watching. Either set " \
                              "HOME or SINCEDB_DIR in your environment, or set sincedb_path in " \
                              "in your Logstash config for the file input with " \
                              "path '#{@path.inspect}'")
                raise(LogStash::ConfigurationError, "Sincedb can not be created.")
            end
            sincedb_dir = ENV["SINCEDB_DIR"] || ENV["HOME"]
            @sincedb_path = File.join(sincedb_dir, ".sincedb_journal")
            @logger.info("No sincedb_path set, generating one for the journal",
                         :sincedb_path => @sincedb_path)
        end
        # (Create and) read sincedb
        FileUtils.touch(@sincedb_path)
        @cursor = IO.read(@sincedb_path)
        # Write sincedb in thread
        @sincedb_writer = Thread.new do
            loop do
                sleep @sincedb_write_interval
                if @cursor != @written_cursor
                    file = File.open(@sincedb_path, 'w+')
                    file.puts @cursor
                    file.close
                    @cursor_lock.synchronize {
                        @written_cursor = @cursor
                    }
                end
            end
        end
    end # def register

    def run(queue)
        if @cursor.strip.length == 0
            @journal.seek(@seekto.to_sym)

            # We must make one movement in order for the journal C api or else
            # the @journal.watch call will start from the beginning of the
            # journal. see:
            # https://github.com/ledbettj/systemd-journal/issues/55
            if @seekto == 'tail'
              @journal.move_previous
            end

            @journal.filter(@filter)
        else
            @journal.seek(@cursor)
            @journal.move_next # Without this, the last event will be read again
        end
        @journal.watch do |entry|
            timestamp = entry.realtime_timestamp
            event = LogStash::Event.new(
                entry.to_h_pretty(@pretty_keys).merge(
                    "@timestamp" => timestamp,
                    "host" => entry._hostname || @hostname,
                    "cursor" => @journal.cursor
                )
            )
            decorate(event)
            queue << event
            @cursor_lock.synchronize {
                @cursor = @journal.cursor
            }
        end
    end # def run

    public
    def teardown # FIXME: doesn't really seem to work...
        return finished unless @journal # Ignore multiple calls

        @logger.debug("journald shutting down.")
        @journal = nil
        Thread.kill(@sincedb_writer)
        # Write current cursor
        file = File.open(@sincedb_path, 'w+')
        file.puts @cursor
        file.close
        @cursor = nil
        finished
    end # def teardown

end # class LogStash::Inputs::Journald

# Monkey patch Systemd::JournalEntry
module Systemd
    class JournalEntry
        def to_h_pretty(is_pretty)
            if is_pretty
              @entry.each_with_object({}) { |(k, v), h|
                    h[$prettyfieldmap.fetch(k.to_sym) { |key| k.downcase.sub(/^_*/, '') }] = v.dup.force_encoding('iso-8859-1').encode('utf-8')
                }
            else
                @entry.each_with_object({}) { |(k, v), h| h[k] = v.dup.force_encoding('iso-8859-1').encode('utf-8') }
            end
        end
    end
end
