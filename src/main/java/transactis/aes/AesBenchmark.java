package transactis.aes;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.CommandLineOptions;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

import static java.util.concurrent.TimeUnit.MILLISECONDS;

@State(Scope.Benchmark)
public class AesBenchmark {
    static private int BUFFER_SIZE=4096;// 2 Mo at a time
    private Cipher c1, c2, c3, c4, c5;
    private SecretKey sk;
    private String benchmarkFilePath = "./src/main/resources/file";
    private String encryptedFilePath = "./src/main/resources/file_enc";
    private ProcessBuilder processBuilder;
    private File benchmarkFile;

    private static final int CHACHA_NONCE_LENGTH = 12;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private static final int CHACHA_KEY_SIZE = 256;
    private SecretKey skc,skg;
    private byte[] nonce;

    @Setup
    public void prepare() throws Exception {
        java.security.Security.addProvider(new BouncyCastleProvider());

        // Default AES key length = 128 bit
        sk = KeyGenerator.getInstance("AES").generateKey();
        skg = KeyGenerator.getInstance("AES").generateKey();
        KeyGenerator keyGen = KeyGenerator.getInstance("ChaCha20");
        keyGen.init(256, SecureRandom.getInstanceStrong());
        skc = keyGen.generateKey();

        byte[] iv = generateRandomBytes(GCM_IV_LENGTH);
        byte[] ivg = generateRandomBytes(GCM_IV_LENGTH);
        (new SecureRandom()).nextBytes(iv);
        IvParameterSpec ips = new IvParameterSpec(iv);

        String AESCTRCipherName = "AES/CTR/NoPadding";
        String AESGCMCipherName = "AES/GCM/NoPadding";

        c1 = Cipher.getInstance(AESCTRCipherName);
        c1.init(Cipher.ENCRYPT_MODE, sk, ips);

        c2 = Cipher.getInstance(AESCTRCipherName, "BC");
        c2.init(Cipher.ENCRYPT_MODE, sk, ips);

        c3 = Cipher.getInstance(AESCTRCipherName);
        c3.init(Cipher.ENCRYPT_MODE, sk, ips);

        c4 = Cipher.getInstance(AESGCMCipherName);
        c4.init(Cipher.ENCRYPT_MODE, skg, new GCMParameterSpec(GCM_TAG_LENGTH * 8, ivg));

        nonce = generateRandomBytes(CHACHA_NONCE_LENGTH);

        c5 = Cipher.getInstance("ChaCha20");
        c5.init(Cipher.ENCRYPT_MODE, skc, new IvParameterSpec(nonce));

        benchmarkFile = new File(benchmarkFilePath);

        // Construct the OpenSSL command for file encryption
        String[] opensslCommand = {
                "openssl",
                "aes-256-cbc",
                "-salt",
                "-in",
                benchmarkFilePath,
                "-out",
                encryptedFilePath,
                "-k",
                sk.toString(),
        };

        // Execute the OpenSSL command
        processBuilder = new ProcessBuilder(opensslCommand);
    }
    public static void main(String[] args) throws Exception {
        Options opt = new OptionsBuilder()
                .jvmArgsAppend("-Djmh.separateClasspathJAR=true")
                .parent(new CommandLineOptions(args))
                .include(".*Benchmark.*")
                .build();

        new Runner(opt).run();
    }
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(MILLISECONDS)
    @Warmup(iterations = 3)
    @Measurement(iterations = 10)
    @Fork(value = 1)
    public void aes_jdk() throws Exception {
        try (FileInputStream inputStream = new FileInputStream(benchmarkFile)){
            c1.update(inputStream.readAllBytes());
        }
        byte[] finaleCipherData = c1.doFinal();
        try(OutputStream outputStream = new FileOutputStream(encryptedFilePath)){
            outputStream.write(c1.getIV());
            outputStream.write(finaleCipherData);
        }
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(MILLISECONDS)
    @Warmup(iterations = 3)
    @Measurement(iterations = 10)
    @Fork(value = 0)
    public void aes_bc() throws Exception {
        try (FileInputStream inputStream = new FileInputStream(benchmarkFile)){
            c2.update(inputStream.readAllBytes());
        }
        byte[] finaleCipherData = c2.doFinal();
        try(OutputStream outputStream = new FileOutputStream(encryptedFilePath)){
            outputStream.write(c2.getIV());
            outputStream.write(finaleCipherData);
        }
    }
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(MILLISECONDS)
    @Warmup(iterations = 3)
    @Measurement(iterations = 10)
    @Fork(value = 0)
    public void aes_openssl_native() throws Exception {
        Process process = processBuilder.start();
//        int exitCode = process.waitFor();
//        if (exitCode == 0) {
//            System.out.println("File encryption completed successfully.");
//        } else {
//            System.err.println("File encryption failed.");
//        }
    }
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(MILLISECONDS)
    @Warmup(iterations = 3)
    @Measurement(iterations = 10)
    @Fork(value = 1)
    public void aes_gcm_jdk() throws Exception {
        try (FileInputStream inputStream = new FileInputStream(benchmarkFile)){
            c4.update(inputStream.readAllBytes());
        }
        byte[] finaleCipherData = c4.doFinal();
        try(OutputStream outputStream = new FileOutputStream(encryptedFilePath)){
            outputStream.write(c4.getIV());
            outputStream.write(finaleCipherData);
        }
    }
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(MILLISECONDS)
    @Warmup(iterations = 3)
    @Measurement(iterations = 10)
    @Fork(value = 1)
    public void chacha20_jdk() throws Exception {
        try (FileInputStream inputStream = new FileInputStream(benchmarkFile)){
            c5.update(inputStream.readAllBytes());
        }
        byte[] finaleCipherData = c5.doFinal();
        try(OutputStream outputStream = new FileOutputStream(encryptedFilePath)){
            outputStream.write(nonce);
            outputStream.write(finaleCipherData);
        }
    }
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(MILLISECONDS)
    @Warmup(iterations = 3)
    @Measurement(iterations = 10)
    @Fork(value = 0)
    public void aes_jdk_buffered() throws Exception {
        byte[] buffer = new byte[BUFFER_SIZE];
        int bytesRead; // cursor

        try (BufferedInputStream inputStream =new BufferedInputStream( new FileInputStream(benchmarkFile)) ){
            try(BufferedOutputStream outputStream = new BufferedOutputStream( new FileOutputStream(encryptedFilePath) ) ) {
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    byte[] cipheredData = c3.update(buffer, 0, bytesRead);
                    outputStream.write(cipheredData);
                }
                byte[] finale = c3.doFinal();
                outputStream.write(finale);
            }
        }
    }
    private static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(bytes);
        return bytes;
    }
}
