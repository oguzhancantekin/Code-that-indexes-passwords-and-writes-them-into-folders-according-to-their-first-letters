import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

public class PasswordProcessor {

    public static void main(String[] args) {
        String unprocessedPasswordsFolderPath = "C:\\Users\\oguzh\\OneDrive\\Masaüstü\\File_Project\\Unprocessed-Passwords";
        String processedPasswordsFilePath = "C:\\Users\\oguzh\\OneDrive\\Masaüstü\\File_Project\\Processed\\Processed.txt";
        String indexFolderPath = "C:\\Users\\oguzh\\OneDrive\\Masaüstü\\File_Project\\Index";
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("Parolaları Indexlemek için 1'e basın.");
            System.out.println("Parola aramak için 2'ye basın.");
            System.out.println("Çıkış yapmak için 0'a basın.");
            int choice = scanner.nextInt();
            scanner.nextLine();  // newline character

            if (choice == 1) {
                processPasswords(unprocessedPasswordsFolderPath, processedPasswordsFilePath, indexFolderPath);
            } else if (choice == 2) {
                System.out.println("Aramak istediğiniz parolayı girin:");
                String password = scanner.nextLine();
                searchPassword(indexFolderPath, password);
            } else if (choice == 0) {
                System.out.println("Programdan çıkılıyor.");
                break;
            } else {
                System.out.println("Geçersiz seçenek. Tekrar deneyin.");
            }
        }

        scanner.close();
    }

    public static void processPasswords(String unprocessedPasswordsFolderPath, String processedPasswordsFilePath, String indexFolderPath) {
        File unprocessedPasswordsFolder = new File(unprocessedPasswordsFolderPath);

        if (!unprocessedPasswordsFolder.exists() || !unprocessedPasswordsFolder.isDirectory()) {
            System.out.println("Unprocessed Passwords folder does not exist.");
            return;
        }

        File[] txtFiles = unprocessedPasswordsFolder.listFiles((dir, name) -> name.toLowerCase().endsWith(".txt"));

        if (txtFiles == null || txtFiles.length == 0) {
            System.out.println("No TXT files found in Unprocessed Passwords folder.");
            return;
        }

        createProcessedFile(processedPasswordsFilePath);
        createIndexFolder(indexFolderPath);
        Set<String> processedPasswordsSet = new HashSet<>();
        Map<String, BufferedWriter> writerMap = new HashMap<>();

        try (BufferedWriter processedPw = new BufferedWriter(new FileWriter(processedPasswordsFilePath, true))) {
            for (File txtFile : txtFiles) {
                try (BufferedReader br = new BufferedReader(new FileReader(txtFile))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        String[] parts = line.split("\\|");
                        if (parts.length == 1) {
                            String password = parts[0];
                            if (!processedPasswordsSet.contains(password)) {
                                String md5Hash = getHash(password, "MD5");
                                String sha128Hash = getHash(password, "SHA-1");
                                String sha256Hash = getHash(password, "SHA-256");

                                savePassword(indexFolderPath, password, md5Hash, sha128Hash, sha256Hash, txtFile.getName(), writerMap);
                                processedPw.write(password);
                                processedPw.newLine();
                                processedPasswordsSet.add(password);
                            }
                        }
                    }
                    clearFileContent(txtFile);
                } catch (IOException e) {
                    System.out.println("An error occurred while processing passwords from file " + txtFile.getName() + ": " + e.getMessage());
                }
            }

            for (BufferedWriter writer : writerMap.values()) {
                try {
                    writer.close();
                } catch (IOException e) {
                    System.out.println("An error occurred while closing writer: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            System.out.println("An error occurred while writing to the processed file: " + e.getMessage());
        }
    }

    public static void clearFileContent(File file) {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(file))) {
            bw.write("");
            System.out.println("Successfully cleared content of file: " + file.getName());
        } catch (IOException e) {
            System.out.println("An error occurred while clearing content of file: " + e.getMessage());
        }
    }

    public static String getHash(String input, String algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] hash = digest.digest(input.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void savePassword(String indexFolderPath, String password, String md5Hash, String sha128Hash, String sha256Hash, String sourceFileName, Map<String, BufferedWriter> writerMap) {
        char firstChar = password.charAt(0);
        String charFolderName;
        String filePath;

        if ("\\/:*?\"<>|.".indexOf(firstChar) != -1) {
            charFolderName = "tanimsiz";
        } else if (Character.isUpperCase(firstChar)) {
            charFolderName = "Buyuk_harfler" + File.separator + firstChar;
        } else {
            charFolderName = String.valueOf(Character.toLowerCase(firstChar));
        }

        String charFolderPath = indexFolderPath + File.separator + charFolderName;
        File charFolder = new File(charFolderPath);

        if (!charFolder.exists()) {
            if (charFolder.mkdirs()) {
                System.out.println("Directory created: " + charFolderPath);
            } else {
                System.out.println("Failed to create directory: " + charFolderPath);
            }
        }

        if (Character.isUpperCase(firstChar)) {
            filePath = charFolderPath + File.separator + firstChar + ".txt";
        } else {
            filePath = charFolderPath + File.separator + charFolderName + ".txt";
        }

        BufferedWriter pw = writerMap.get(filePath);
        if (pw == null) {
            try {
                pw = new BufferedWriter(new FileWriter(filePath, true));
                writerMap.put(filePath, pw);
            } catch (IOException e) {
                System.out.println("An error occurred while creating writer for file: " + filePath + " - " + e.getMessage());
                return;
            }
        }

        try {
            pw.write(password + "|" + md5Hash + "|" + sha128Hash + "|" + sha256Hash + "|" + sourceFileName);
            pw.newLine();
        } catch (IOException e) {
            System.out.println("An error occurred while writing the password to file: " + e.getMessage());
        }
    }

    public static void searchPassword(String indexFolderPath, String password) {
        char firstChar = password.charAt(0);
        String charFolderName;

        if ("\\/:*?\"<>|.".indexOf(firstChar) != -1) {
            charFolderName = "tanimsiz";
        } else if (Character.isUpperCase(firstChar)) {
            charFolderName = "Buyuk_harfler" + File.separator + firstChar;
        } else {
            charFolderName = String.valueOf(Character.toLowerCase(firstChar));
        }

        String charFolderPath = indexFolderPath + File.separator + charFolderName;
        File charFolder = new File(charFolderPath);

        if (!charFolder.exists()) {
            System.out.println("Klasör bulunamadı Indexleme yaptığınızdan emin olun: " + charFolderPath);
            return;
        }

        File[] txtFiles = charFolder.listFiles((dir, name) -> name.toLowerCase().endsWith(".txt"));

        if (txtFiles == null || txtFiles.length == 0) {
            System.out.println("Şifre dosyaları bulunamadı: " + charFolderPath);
            return;
        }

        boolean found = false;
        for (File txtFile : txtFiles) {
            try (BufferedReader br = new BufferedReader(new FileReader(txtFile))) {
                String line;
                while ((line = br.readLine()) != null) {
                    if (line.startsWith(password + "|")) {
                        System.out.println("Şifre bulundu: " + txtFile.getPath());
                        found = true;
                        break;
                    }
                }
            } catch (IOException e) {
                System.out.println("Dosya okunurken hata oluştu: " + txtFile.getName());
            }

            if (found) break;
        }

        if (!found) {
            System.out.println("Şifre bulunamadı. Yeni şifre ekleniyor.");
            addPasswordToIndex(indexFolderPath, password);
        }
    }

    public static void addPasswordToIndex(String indexFolderPath, String password) {
        String md5Hash = getHash(password, "MD5");
        String sha128Hash = getHash(password, "SHA-1");
        String sha256Hash = getHash(password, "SHA-256");

        Map<String, BufferedWriter> writerMap = new HashMap<>();
        savePassword(indexFolderPath, password, md5Hash, sha128Hash, sha256Hash, "UserInput", writerMap);

        for (BufferedWriter writer : writerMap.values()) {
            try {
                writer.close();
            } catch (IOException e) {
                System.out.println("An error occurred while closing writer: " + e.getMessage());
            }
        }
    }

    public static void createProcessedFile(String processedPasswordsFilePath) {
        File processedPasswordsFile = new File(processedPasswordsFilePath);
        if (!processedPasswordsFile.exists()) {
            try {
                if (processedPasswordsFile.createNewFile()) {
                    System.out.println("Processed passwords file created: " + processedPasswordsFilePath);
                } else {
                    System.out.println("Failed to create processed passwords file: " + processedPasswordsFilePath);
                }
            } catch (IOException e) {
                System.out.println("An error occurred while creating processed passwords file: " + e.getMessage());
            }
        }
    }

    public static void createIndexFolder(String indexFolderPath) {
        File indexFolder = new File(indexFolderPath);
        if (!indexFolder.exists()) {
            if (indexFolder.mkdirs()) {
                System.out.println("Index folder created: " + indexFolderPath);
            } else {
                System.out.println("Failed to create index folder: " + indexFolderPath);
            }
        }
    }
}