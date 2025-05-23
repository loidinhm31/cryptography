package org.simple.mail.util;

import java.sql.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;

public class Database {
    public final static String DB_NAME = "maildb";
    public final static String ACCOUNT = "mailadmin";
    public final static String PASSWORD = "123456";
    private final static String URL_PREFIX = "jdbc:mysql://127.0.0.1:3306/";

    Statement stmt;
    private final Connection conn;

    public Database(String dbName, String account, String password) throws SQLException {
        StringBuilder url = new StringBuilder(URL_PREFIX);
        url.append(dbName);
        conn = DriverManager.getConnection(url.toString(), account, password);
        stmt = conn.createStatement();
    }

    public int insertMail(Mail mail) {
        int ret = 0;
        String query = "INSERT INTO tbl_mails (date, sender, recipient, body) VALUES (?, ?, ?, ?);";
        try (PreparedStatement insertStmt = conn.prepareStatement(query)
        ) {
            DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
            String timeString = dateFormat.format(mail.getReceivedTime());

            insertStmt.setTimestamp(1, Timestamp.valueOf(timeString));
            insertStmt.setString(2, mail.getSender());
            insertStmt.setString(3, mail.getRecipient());
            insertStmt.setString(4, mail.getBody());

            ret = insertStmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return ret;
    }

    public Mail retrieveMail(String recipient, int id) {
        Mail mail = null;
        String query = "SELECT * FROM tbl_mails WHERE recipient = ? AND id = ?;";
        try (PreparedStatement selectStmt = conn.prepareStatement(query)) {
            selectStmt.setString(1, recipient);
            selectStmt.setInt(2, id);
            ResultSet rs = selectStmt.executeQuery();
            if (rs.next()) {
                mail = new Mail();
                mail.setId(rs.getInt("id"));
                mail.setSender(rs.getString("sender"));
                mail.setRecipient(rs.getString("recipient"));
                mail.setBody(rs.getString("body"));
                mail.setTime(rs.getTimestamp("date"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return mail;
    }

    public ArrayList<Mail> retrieveMailList(String recipient) {
        ArrayList<Mail> list = new ArrayList<Mail>();
        String query = "SELECT * FROM tbl_mails WHERE recipient = ?;";
        try (PreparedStatement selectStmt = conn.prepareStatement(query)
        ) {
            selectStmt.setString(1, recipient);
            ResultSet rs = selectStmt.executeQuery();

            while (rs.next()) {
                Mail mail = new Mail();
                mail.setId(rs.getInt("id"));
                mail.setSender(rs.getString("sender"));
                mail.setRecipient(rs.getString("recipient"));
                mail.setTime(rs.getTimestamp("date"));
                list.add(mail);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }

    public int deleteMail(String recipient, int id) {
        int ret = 0;
        String query = "DELETE FROM tbl_mails WHERE recipient = ? AND id = ?;";
        try (PreparedStatement deleteStmt = conn.prepareStatement(query)
        ) {
            deleteStmt.setString(1, recipient);
            deleteStmt.setInt(2, id);
            ret = deleteStmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return ret;
    }
}