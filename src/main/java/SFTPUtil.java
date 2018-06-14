

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpException;

public class SFTPUtil {

    public void upload() throws SftpException {
        Session session = null;
        String host = "127.0.0.1";
        int port = 22;
        String username = "user";
        String password = "pwd";
        try {
            JSch jsch = new JSch();

            session = jsch.getSession(username, host, port);
            session.setConfig("StrictHostKeyChecking", "no");
            session.setPassword(password);
            session.connect();

            Channel channel = session.openChannel("sftp");
            channel.connect();

            ChannelSftp sftpChannel = (ChannelSftp) channel;

            sftpChannel.cd("..path/to/folder");

            String fileName = "tgtfile.pdf";
            String sourceFilePath = "/path/to/source/file/srcfile.pdf";
            sftpChannel.put(sourceFilePath, fileName, ChannelSftp.OVERWRITE);
            sftpChannel.exit();

        } catch (JSchException | SftpException e) {
            e.printStackTrace();
        } finally {
            if (session != null && session.isConnected()) {
                session.disconnect();
            }
        }
    }

}
