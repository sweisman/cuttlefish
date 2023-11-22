package cf;
use strict;

use Socket ();
use IO::Compress::Gzip ();

sub check
{
    my $id = shift or return;

    if (!(-S "$cmf::CF_BASE/pipes/$id"))
    {
        cmf::debug("CF check '$id' no pipe");
        my $pid = util::data_load("$cmf::CF_BASE/pipes/$id.pid");
        $pid =~ s/\D+//g;
        if ($pid)
        {
            cmf::debug("CF check '$id' kill process $pid");
            kill 'KILL', $pid;
            unlink("$cmf::CF_BASE/pipes/$id.pid");
        }
        return;
    }

    my $result = cmd($id, 'STATUS');
    if (!$result)
    {
        cmf::debug("CF check '$id' no status");
        return;
    }

    if ($result !~ /LAST_PING=T-(\d+)/)
    {
        cmf::debug("CF check '$id' bad status format:", $result, '===');
        cmd($id, 'CLOSE');
        return;
    }
    elsif ($1 > 30)
    {
        cmf::debug("CF check '$id' keepalive timeout exceeded at $1 seconds");
        cmd($id, 'CLOSE');
        return;
    }

    return 1;
}

sub cmd_file
{
    my $id = shift;
    my $file = shift or return;
    my $data = shift;
    my ($ref, $send, $tmp, $compress);

    return unless check($id);

    if ($data)
    {
        $send = 1;
        $ref = (ref($data) ? $data : \$data);
    }

    if ($send)
    {
        if ($file !~ /apro/i)
        {
            if (length($$ref) > 1024 && $file !~ /\.(?:gz|zip)$/i)
            {
                $file .= '.gz';

                if (!IO::Compress::Gzip::gzip($ref => \$compress))
                {
                    cmf::debug("cf::cmd_file: gzip failed: '$IO::Compress::Gzip::GzipError'");
                    return;
                }

                $ref = \$compress;
            }

            cmd_exec($id, qq{cmd /C del "$file"});
        }
    }

    my $port = cmd_connect($id, "FILE 0 $file");
    if (!$port)
    {
        cmf::debug("ERROR: '$id' FILE 0 $send $file");
        return;
    }

    if ($send)
    {
# xxx check return values
        _port($port, $ref);
        _wait($id, $port);
        sleep(1); # xxx test shorter periods

# xxx check return values and return actual status
        cmd_exec($id, qq{gzip -d -f "$file"}) if $compress;
        return;
    }

    my $data = _port($port);
    _wait($id, $port);
    return $data;
}

sub cmd_exec
{
    my $id = shift;
    my $command = shift;
    my $keep_alive = shift;

    return unless check($id);

    # list contents of a directory
    # cfpipe user001 "COMMAND 0 cmd /C dir \"c:\\Program Files\\\""
    # get the remote DOS command line
    # cfpipe user001 "COMMAND 0 cmd /K"

    # xxx put timeout here
    my $port = cmd_connect($id, "EXEC 0 $command") or return;
    return $port if $keep_alive;
    my $data = _port($port);
    _wait($id, $port);
    return $data;
}

sub cmd_connect
{
    my $id = shift;
    my $command = shift;

    return unless check($id);

    my $response = cmd($id, $command);
    return if index($response, 'SUCC') < 0;
    return $1 if $response =~ /(\d+)\s*$/;
    cmf::debug("cf::cmd_connect: invalid response '$response' for id $id and command '$command'");
    return;
}

sub cmd
{
    my $path = "$cmf::CF_BASE/pipes/" . shift;
    my $data = shift or return;
    $data .= ' ';

    if (!(-S $path))
    {
        cmf::debug("cf::cmd $path '$data': invalid or not found");
        return;
    }

    if (!socket(SOCK, Socket::PF_UNIX(), Socket::SOCK_STREAM(), 0))
    {
        cmf::debug("cf::cmd $path '$data': socket error: $!");
        return;
    }

    if (!connect(SOCK, Socket::sockaddr_un($path)))
    {
        cmf::debug("cf::cmd $path '$data': connect error: $!");
        return;
    }

    if (syswrite(SOCK, $data) != length($data))
    {
        cmf::debug("cf::cmd $path '$data': syswrite error");
        return;
    }

    my ($rv, $rin, $len, $response);

    vec($rin, fileno(SOCK), 1) = 1;

    do
    {
        $rv = select($rin, undef, undef, 10);
        cmf::debug("cf::cmd $path '$data': select error: $!") if $rv < 0;
        last if $rv < 1;

        $len = sysread(SOCK, $data, 200);
        $response .= $data;

    } while ($len);

    close(SOCK);

    return $response;
}

sub _port
{
    my $port = shift or return;
    my $data = shift;
    my ($sock, $response);

    if (!socket($sock, Socket::PF_INET(), Socket::SOCK_STREAM(), getprotobyname('tcp')))
    {
        cmf::debug("ERROR cf::port: socket error: $!");
        return;
    }

    if (!connect($sock, Socket::sockaddr_in($port, Socket::INADDR_LOOPBACK())))
    {
        cmf::debug("ERROR cf::port: connect error: $!");
        return;
    }

    my $ref = (ref($data) ? $data : \$data);

    my ($rv, $vin, $vout, $len);

    vec($vin, fileno($sock), 1) = 1;

    if ($$ref)
    {
        my $i = 0;

        #my $old_sock = select($sock); $| = 1; select($old_sock);
        #setsockopt($sock, SOL_SOCKET, SO_LINGER, pack('i2', 1, 16));
#        $response = print $sock $$ref;
#        $response = syswrite($sock, $$ref);
#        return close($sock) && $response;

        do
        {
            $rv = select(undef, $vout = $vin, undef, 10);

            if ($rv < 0)
            {
                cmf::debug("ERROR cf::_port: write select error: $!");
                last;
            }
            elsif (!$rv)
            {
                cmf::debug('ERROR cf::_port: $rv == 0');
                next;
            }

            $len += syswrite($sock, $$ref, 512, $i);
            $i += 512;
        } while $len < length($$ref);

        if ($len == length($$ref))
        {
            select(undef, $vout = $vin, undef, 10);
            $response = 1;
        }

        #$response = syswrite($sock, $$ref);
        return close($sock) && $response;
    }

    do
    {
        $rv = select($vout = $vin, undef, undef, 60);

        if ($rv > 0)
        {
            $len = sysread($sock, $data, 2048);
            $response .= $data;
#~ cmf::debug("read data " . length($data));
        }
        elsif ($rv < 0)
        {
            cmf::debug("ERROR cf::_port: rv == '$rv', read select error: $!");
        }
    } while ($len && $rv > 0);

    close($sock);
    return $response;
}

sub _wait
{
    select(undef, undef, undef, 0.1) while cmd($_[0], 'LIST') =~ /\bLOCALPORT=$_[1]\b/;
}

1;

__END__

cfpipe is a BASH script that simplifies using CF command pipes from the command line

cfpipe user001 STATUS
cfpipe user001 LIST
cfpipe user001 CLOSE
# get time
cfpipe user001 "CONNECT 0 localhost 13"

if (0)
{
    if ($send)
    {
        $tmp = "$cmf::TMP/eki-cf-file-$$";
        open(my $fh, '>', $tmp);
        if ($compress)
        {
            if (!IO::Compress::Gzip::gzip($data => $fh))
            {
                cmf::debug("cf::cmd_file: gzip failed: '$IO::Compress::Gzip::GzipError'");
                return;
            }
        }
        else
        {
            print $fh $$data;
        }
        close($fh);

        `cat $tmp | nc localhost $port -q1`;
        # select(undef, undef, undef, 0.1) while cmd($id, 'LIST') =~ /\bLOCALPORT=$port\b/;
        unlink($tmp);

        cmd_exec($id, qq{gzip -d "$file"}) if $compress;

        # cmd($id, 'COMPRESSION -');
        return;
    }
}
