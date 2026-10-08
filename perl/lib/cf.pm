package cf;
use strict;
use warnings;
use Socket ();
use IO::Socket::UNIX;
use IO::Socket::INET;
use IO::Select;
use Digest::SHA qw(sha256_hex);
use Time::HiRes qw(time sleep);

# Existing callers configure $cmf::CF_BASE. Endpoints are TCP ports in legacy
# mode and owner-only Unix socket paths in v2.
my %operations;

sub _path { no warnings 'once'; return "$cmf::CF_BASE/pipes/$_[0]"; }
sub _write_all {
    my ($socket, $data) = @_;
    my $offset = 0;
    my $deadline = time + 30;
    my $select = IO::Select->new($socket);
    while ($offset < length($data)) {
        die "cuttlefish write timeout\n" if time >= $deadline;
        next unless $select->can_write(0.1);
        my $count = syswrite($socket, $data, length($data) - $offset, $offset);
        die "cuttlefish write failed: $!\n" unless defined($count) && $count > 0;
        $offset += $count;
        $deadline = time + 30;
    }
}

sub _read_all {
    my ($socket, $limit) = @_;
    my $data = '';
    my $select = IO::Select->new($socket);
    while (1) {
        die "cuttlefish read timeout\n" unless $select->can_read(30);
        my $count = sysread($socket, my $chunk, 8192);
        die "cuttlefish read failed: $!\n" unless defined $count;
        last unless $count;
        die "cuttlefish response limit exceeded\n" if length($data) + $count > $limit;
        $data .= $chunk;
    }
    return $data;
}

sub cmd {
    my ($id, $command) = @_;
    die "invalid cuttlefish command\n" unless defined($command) && length($command) < 1024 && $command !~ /[\r\n\0]/;
    my $socket = IO::Socket::UNIX->new(Type => Socket::SOCK_STREAM(), Peer => _path($id))
        or die "cuttlefish control connect failed: $!\n";
    _write_all($socket, "$command\n");
    my $response = _read_all($socket, 128 * 1024);
    close($socket);
    return $response;
}

sub check {
    my $id = shift;
    return unless defined($id) && -S _path($id);
    my $status = cmd($id, 'STATUS');
    return $status =~ /LAST_PING=T-(\d+)/ && $1 <= 30;
}

sub cmd_connect {
    my ($id, $command) = @_;
    my $response = cmd($id, $command);
    if ($response =~ /^\w+ SUCCESS (\d+) (\/[^\r\n]+)\n$/) {
        $operations{$2} = [$id, $1];
        return $2;
    }
    return $1 if $response =~ /^\w+ SUCCESS (\d+)\n$/;
    die "cuttlefish: $response";
}

sub _port {
    my ($endpoint, $data) = @_;
    my $socket = $endpoint =~ m{^/}
        ? IO::Socket::UNIX->new(Type => Socket::SOCK_STREAM(), Peer => $endpoint)
        : IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $endpoint, Proto => 'tcp', Timeout => 30);
    die "cuttlefish data connect failed: $!\n" unless $socket;
    if (defined $data) {
        my $bytes = ref($data) ? $$data : $data;
        _write_all($socket, $bytes);
        shutdown($socket, 1) or die "cuttlefish shutdown failed: $!\n";
        my $unexpected = _read_all($socket, 8192);
        die "cuttlefish upload unexpectedly received data (legacy FILE direction mismatch)\n" if length($unexpected);
        close($socket);
        return 1;
    }
    shutdown($socket, 1) if exists $operations{$endpoint};
    my $response = _read_all($socket, 8 * 1024 * 1024);
    close($socket);
    return $response;
}

sub _wait {
    my ($id, $endpoint) = @_;
    my $deadline = time + 30;
    while (time < $deadline) {
        if (my $operation = $operations{$endpoint}) {
            my $response = cmd($id, "RESULT $operation->[1]");
            if ($response =~ /^OK(?:\s|$)/) { delete $operations{$endpoint}; return 1; }
            die "cuttlefish: $response" unless $response eq "PENDING\n";
        } else {
            return 1 unless cmd($id, 'LIST') =~ /\bLOCAL_PORT=\Q$endpoint\E\b/;
        }
        sleep(0.05);
    }
    die "cuttlefish completion timeout\n";
}

sub cmd_exec {
    my ($id, $command, $keep_alive) = @_;
    my $endpoint = cmd_connect($id, "EXEC 0 $command");
    return $endpoint if $keep_alive;
    my $data = _port($endpoint);
    _wait($id, $endpoint);
    return $data;
}

sub cmd_file {
    my ($id, $file, $data) = @_;
    my $v2 = cmd($id, 'STATUS') =~ /PROTOCOL=v2/;
    my $command;
    if (defined($data) && $v2) {
        my $bytes = ref($data) ? $$data : $data;
        $command = 'PUT 0 ' . length($bytes) . ' ' . sha256_hex($bytes) . " $file";
    } else {
        $command = ($v2 ? 'GET' : 'FILE') . " 0 $file";
    }
    my $endpoint = cmd_connect($id, $command);
    my $response = _port($endpoint, $data);
    _wait($id, $endpoint);
    return $response;
}

1;
