import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.util.concurrent.*;
import java.math.BigInteger;

public class ServidorPrincipal {
    private static final int PUERTO = 8080;
    private static final String CLAVE_PRIVADA_PATH = "server_priv.der";
    private static final String CLAVE_PUBLICA_PATH = "server_pub.der";
    private static final Map<String, String> servicios = new HashMap<>();
    
    // Estadísticas para mediciones
    private static final ConcurrentHashMap<String, List<Long>> tiempos = new ConcurrentHashMap<>();
    
    static {
        servicios.put("1", "Consulta de vuelo|192.168.1.1|8081");
        servicios.put("2", "Disponibilidad de vuelos|192.168.1.2|8082");
        servicios.put("3", "Costo de vuelo|192.168.1.3|8083");
        
        // Inicializar listas para mediciones
        tiempos.put("firma", new ArrayList<>());
        tiempos.put("cifrado_tabla", new ArrayList<>());
        tiempos.put("verificacion_consulta", new ArrayList<>());
        tiempos.put("cifrado_simetrico", new ArrayList<>());
        tiempos.put("cifrado_asimetrico", new ArrayList<>());
    }

    public static void main(String[] args) throws Exception {
        // Generar llaves RSA si no existen
        if (!Files.exists(Paths.get(CLAVE_PRIVADA_PATH)) || !Files.exists(Paths.get(CLAVE_PUBLICA_PATH))) {
            generarYGuardarLlavesRSA();
        }
        
        // Solicitar número de delegados por entrada de usuario
        Scanner scanner = new Scanner(System.in);
        System.out.print("Ingrese el número de delegados (1 para modo iterativo): ");
        int numDelegados = 1;
        
        try {
            numDelegados = scanner.nextInt();
            if (numDelegados < 1) {
                System.out.println("El número de delegados debe ser al menos 1. Usando 1 delegado.");
                numDelegados = 1;
            }
        } catch (InputMismatchException e) {
            System.out.println("Entrada inválida. Usando 1 delegado por defecto.");
        }
        
        System.out.println("Iniciando servidor con " + numDelegados + " delegados");

        try (ServerSocket serverSocket = new ServerSocket(PUERTO)) {
            System.out.println("Servidor escuchando en el puerto " + PUERTO);
            
            // Para escenario de un solo cliente iterativo
            if (numDelegados == 1) {
                while (true) {
                    Socket clientSocket = serverSocket.accept();
                    System.out.println("Cliente conectado desde " + clientSocket.getInetAddress());
                    new ClientHandler(clientSocket).run();
                }
            } 
            // Para escenarios concurrentes
            else {
                ExecutorService executor = Executors.newFixedThreadPool(numDelegados);
                CountDownLatch latch = new CountDownLatch(numDelegados);
                
                for (int i = 0; i < numDelegados; i++) {
                    executor.submit(() -> {
                        try {
                            Socket clientSocket = serverSocket.accept();
                            System.out.println("Cliente conectado desde " + clientSocket.getInetAddress());
                            new ClientHandler(clientSocket, latch).run();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    });
                }
                
                latch.await(); // Esperar a que todos los delegados terminen
                executor.shutdown();
                
                // Mostrar estadísticas
                mostrarEstadisticas();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    private static void mostrarEstadisticas() {
        System.out.println("\n--- ESTADÍSTICAS ---");
        
        System.out.println("Tiempos de firma (ms): " + calcularEstadisticas(tiempos.get("firma")));
        System.out.println("Tiempos de cifrado de tabla (ms): " + calcularEstadisticas(tiempos.get("cifrado_tabla")));
        System.out.println("Tiempos de verificación de consulta (ms): " + calcularEstadisticas(tiempos.get("verificacion_consulta")));
        System.out.println("Tiempos de cifrado simétrico (ms): " + calcularEstadisticas(tiempos.get("cifrado_simetrico")));
        System.out.println("Tiempos de cifrado asimétrico (ms): " + calcularEstadisticas(tiempos.get("cifrado_asimetrico")));
    }
    
    private static String calcularEstadisticas(List<Long> tiempos) {
        if (tiempos.isEmpty()) return "No hay datos";
        
        double suma = 0;
        long min = Long.MAX_VALUE;
        long max = Long.MIN_VALUE;
        
        for (Long tiempo : tiempos) {
            suma += tiempo;
            min = Math.min(min, tiempo);
            max = Math.max(max, tiempo);
        }
        
        double promedio = suma / tiempos.size();
        return String.format("Min: %d, Max: %d, Promedio: %.2f, Total: %d", min, max, promedio, tiempos.size());
    }

    private static void generarYGuardarLlavesRSA() throws IOException, NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        try (FileOutputStream fos = new FileOutputStream(CLAVE_PRIVADA_PATH)) {
            fos.write(privateKey.getEncoded());
        }

        try (FileOutputStream fos = new FileOutputStream(CLAVE_PUBLICA_PATH)) {
            fos.write(publicKey.getEncoded());
        }

        System.out.println("Llaves RSA generadas y guardadas en formato DER.");
    }

    private static class ClientHandler implements Runnable {
        private Socket clientSocket;
        private CountDownLatch latch;

        public ClientHandler(Socket clientSocket) {
            this.clientSocket = clientSocket;
        }
        
        public ClientHandler(Socket clientSocket, CountDownLatch latch) {
            this.clientSocket = clientSocket;
            this.latch = latch;
        }

        @Override
        public void run() {
            try {
                // Cargar la clave privada RSA del servidor (para firmar)
                PrivateKey privateKeyRSA = cargarClavePrivada(CLAVE_PRIVADA_PATH);
                PublicKey publicKeyRSA = cargarClavePublica(CLAVE_PUBLICA_PATH);
                
                // Establecimiento de sesión con Diffie-Hellman
                // 1. Generar par de claves DH para el servidor
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
                keyGen.initialize(1024);
                KeyPair keyPair = keyGen.generateKeyPair();
                
                // 2. Recibir clave pública DH del cliente
                ObjectInputStream ois = new ObjectInputStream(clientSocket.getInputStream());
                PublicKey publicKeyCliente = (PublicKey) ois.readObject();
                System.out.println("Clave pública DH del cliente recibida.");
                
                // 3. Enviar clave pública DH del servidor
                ObjectOutputStream oos = new ObjectOutputStream(clientSocket.getOutputStream());
                oos.writeObject(keyPair.getPublic());
                oos.flush();
                System.out.println("Clave pública DH enviada al cliente.");
                
                // 4. Generar llave maestra
                KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
                keyAgreement.init(keyPair.getPrivate());
                keyAgreement.doPhase(publicKeyCliente, true);
                byte[] llaveMaestra = keyAgreement.generateSecret();
                
                // 5. Generar digest SHA-512 de la llave maestra
                MessageDigest sha = MessageDigest.getInstance("SHA-512");
                byte[] digest = sha.digest(llaveMaestra);
                
                // 6. Partir el digest en dos mitades
                byte[] aesKeyBytes = Arrays.copyOfRange(digest, 0, 32); // Primeros 256 bits para AES
                byte[] hmacKeyBytes = Arrays.copyOfRange(digest, 32, 64); // Últimos 256 bits para HMAC
                
                // 7. Crear llaves
                SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");
                SecretKeySpec hmacKey = new SecretKeySpec(hmacKeyBytes, "HmacSHA256");
                
                // Enviar tabla de servicios cifrada
                DataOutputStream dos = new DataOutputStream(clientSocket.getOutputStream());
                DataInputStream dis = new DataInputStream(clientSocket.getInputStream());
                
                // Preparar tabla de servicios
                StringBuilder tablaBuilder = new StringBuilder();
                for (Map.Entry<String, String> entry : servicios.entrySet()) {
                    String[] partes = entry.getValue().split("\\|");
                    tablaBuilder.append(entry.getKey()).append(":").append(partes[0]).append("\n");
                }
                String tablaServicios = tablaBuilder.toString().trim();
                byte[] tablaBytes = tablaServicios.getBytes();
                
                // Firmar la tabla con RSA
                long tiempoInicioFirma = System.nanoTime();
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign(privateKeyRSA);
                signature.update(tablaBytes);
                byte[] firma = signature.sign();
                long tiempoFinFirma = System.nanoTime();
                tiempos.get("firma").add((tiempoFinFirma - tiempoInicioFirma) / 1_000_000);
                
                // Cifrar tabla con AES
                long tiempoInicioCifrado = System.nanoTime();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                byte[] iv = new byte[16];
                new SecureRandom().nextBytes(iv);
                cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
                byte[] tablaCifrada = cipher.doFinal(tablaBytes);
                long tiempoFinCifrado = System.nanoTime();
                tiempos.get("cifrado_tabla").add((tiempoFinCifrado - tiempoInicioCifrado) / 1_000_000);
                
                // Enviar IV, longitud y tabla cifrada
                dos.write(iv);
                dos.writeInt(tablaCifrada.length);
                dos.write(tablaCifrada);
                
                // Enviar longitud y firma
                dos.writeInt(firma.length);
                dos.write(firma);
                
                // Calcular y enviar HMAC
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(hmacKey);
                byte[] hmacTabla = mac.doFinal(tablaCifrada);
                dos.write(hmacTabla);
                
                System.out.println("Tabla de servicios cifrada enviada al cliente.");
                
                // Recibir consulta del cliente
                // Leer IV
                byte[] ivCliente = new byte[16];
                dis.readFully(ivCliente);
                IvParameterSpec ivSpecCliente = new IvParameterSpec(ivCliente);
                
                // Leer mensaje cifrado
                int longitudMensaje = dis.readInt();
                byte[] mensajeCifrado = new byte[longitudMensaje];
                dis.readFully(mensajeCifrado);
                System.out.println("Consulta cifrada recibida.");
                
                // Leer HMAC
                byte[] hmacRecibido = new byte[mac.getMacLength()];
                dis.readFully(hmacRecibido);
                
                // Verificar HMAC
                long tiempoInicioVerificacion = System.nanoTime();
                byte[] hmacCalculado = mac.doFinal(mensajeCifrado);
                boolean hmacValido = Arrays.equals(hmacRecibido, hmacCalculado);
                long tiempoFinVerificacion = System.nanoTime();
                tiempos.get("verificacion_consulta").add((tiempoFinVerificacion - tiempoInicioVerificacion) / 1_000_000);
                
                if (!hmacValido) {
                    System.out.println("Error: HMAC no coincide");
                    dos.writeUTF("Error en la consulta");
                    return;
                }
                
                // Descifrar consulta
                cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpecCliente);
                byte[] consultaDescifrada = cipher.doFinal(mensajeCifrado);
                String idServicio = new String(consultaDescifrada);
                System.out.println("Consulta procesada: " + idServicio);
                
                // Procesar consulta
                String respuesta = servicios.getOrDefault(idServicio, "-1|-1");
                
                // Cifrado simétrico (AES)
                long tiempoInicioCifradoSim = System.nanoTime();
                byte[] ivRespuesta = new byte[16];
                new SecureRandom().nextBytes(ivRespuesta);
                cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(ivRespuesta));
                byte[] respuestaCifrada = cipher.doFinal(respuesta.getBytes());
                long tiempoFinCifradoSim = System.nanoTime();
                tiempos.get("cifrado_simetrico").add((tiempoFinCifradoSim - tiempoInicioCifradoSim) / 1_000_000);
                
                // Cifrado asimétrico (RSA) - Solo para comparación de tiempos
                long tiempoInicioCifradoAsim = System.nanoTime();
                Cipher cipherRSA = Cipher.getInstance("RSA");
                cipherRSA.init(Cipher.ENCRYPT_MODE, publicKeyRSA);
                byte[] respuestaCifradaRSA = cipherRSA.doFinal(respuesta.getBytes());
                long tiempoFinCifradoAsim = System.nanoTime();
                tiempos.get("cifrado_asimetrico").add((tiempoFinCifradoAsim - tiempoInicioCifradoAsim) / 1_000_000);
                
                // Enviar respuesta cifrada con AES
                dos.write(ivRespuesta);
                dos.writeInt(respuestaCifrada.length);
                dos.write(respuestaCifrada);
                
                // Calcular y enviar HMAC de la respuesta
                byte[] hmacRespuesta = mac.doFinal(respuestaCifrada);
                dos.write(hmacRespuesta);
                
                System.out.println("Respuesta enviada al cliente: " + respuesta);
                
                clientSocket.close();
                System.out.println("Conexión cerrada.");
                
                if (latch != null) {
                    latch.countDown();
                }
                
            } catch (Exception e) {
                e.printStackTrace();
                if (latch != null) {
                    latch.countDown();
                }
            }
        }

        private PrivateKey cargarClavePrivada(String ruta) throws Exception {
            byte[] keyBytes = Files.readAllBytes(Paths.get(ruta));
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(spec);
        }
        
        private PublicKey cargarClavePublica(String ruta) throws Exception {
            byte[] keyBytes = Files.readAllBytes(Paths.get(ruta));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(spec);
        }
    }
}
