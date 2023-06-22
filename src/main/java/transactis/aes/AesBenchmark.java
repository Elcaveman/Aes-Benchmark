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
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

import static java.util.concurrent.TimeUnit.MILLISECONDS;

@State(Scope.Benchmark)
public class AesBenchmark {
    static private int BUFFER_SIZE=200000;// 2 Mo at a time
    private Cipher c1, c2, c3;
    private SecretKey sk;
    private String benchmarkFilePath = "./src/main/resources/file.txt";
    private String encryptedFilePath = "./src/main/resources/file_enc.txt";
    private ProcessBuilder processBuilder;
    private File benchmarkFile;

    @Setup
    public void prepare() throws Exception {
        java.security.Security.addProvider(new BouncyCastleProvider());

        // Default AES key length = 128 bit
        sk = KeyGenerator.getInstance("AES").generateKey();
        byte[] iv = new byte[16];
        (new SecureRandom()).nextBytes(iv);
        IvParameterSpec ips = new IvParameterSpec(iv);

        String cipherName = "AES/CTR/NoPadding";

        c1 = Cipher.getInstance(cipherName);
        c1.init(Cipher.ENCRYPT_MODE, sk, ips);

        c2 = Cipher.getInstance(cipherName, "BC");
        c2.init(Cipher.ENCRYPT_MODE, sk, ips);

        c3 = Cipher.getInstance(cipherName);
        c3.init(Cipher.ENCRYPT_MODE, sk, ips);

        byte[] ptxt = new byte[1 << 5000000];//50 Mo file
        benchmarkFile = new File(benchmarkFilePath);
        try (FileOutputStream outputStream = new FileOutputStream(benchmarkFile)) {
            outputStream.write(ptxt);
        }
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
    @Warmup(iterations = 4)
    @Measurement(iterations = 20)
    @Fork(value = 1)
    public void aes_jdk() throws Exception {
        try (FileInputStream inputStream = new FileInputStream(benchmarkFile)){
            c1.update(inputStream.readAllBytes());
        }
        byte[] finaleCipherData = c1.doFinal();
        try(OutputStream outputStream = new FileOutputStream(encryptedFilePath)){
            outputStream.write(finaleCipherData);
        }
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(MILLISECONDS)
    @Warmup(iterations = 4)
    @Measurement(iterations = 20)
    @Fork(value = 1)
    public void aes_bc() throws Exception {
        try (FileInputStream inputStream = new FileInputStream(benchmarkFile)){
            c2.update(inputStream.readAllBytes());
        }
        byte[] finaleCipherData = c2.doFinal();
        try(OutputStream outputStream = new FileOutputStream(encryptedFilePath)){
            outputStream.write(finaleCipherData);
        }
    }
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(MILLISECONDS)
    @Warmup(iterations = 4)
    @Measurement(iterations = 20)
    @Fork(value = 1)
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
    @Warmup(iterations = 4)
    @Measurement(iterations = 20)
    @Fork(value = 1)
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
}
