import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ClienteConsulta {
    private static final String HOST = "localhost";
    private static final int PUERTO = 8080;
    private static final String CLAVE_PUBLICA_SERVIDOR_PATH = "server_pub.der";
    
    private static final ConcurrentHashMap<String, List<Long>> tiempos = new ConcurrentHashMap<>();
    
    static {
        tiempos.put("conexion", new ArrayList<>());
        tiempos.put("descifrado", new ArrayList<>());
        tiempos.put("verificacion", new ArrayList<>());
    }

    public static void main(String[] args) {
        // Solicitar número de clientes y consultas por entrada de usuario
        Scanner scanner = new Scanner(System.in);
        
        // Preguntar si se desea ejecutar en modo automático o manual
        System.out.println("¿Desea ejecutar en modo automático? (S/N)");
        String modoAutomatico = scanner.nextLine().trim().toUpperCase();
        
        if (modoAutomatico.equals("S")) {
            System.out.println("=== MODO AUTOMÁTICO ACTIVADO ===");
            System.out.println("Seleccione el escenario de prueba:");
            System.out.println("1. Un cliente iterativo (32 consultas)");
            System.out.println("2. 4 clientes concurrentes");
            System.out.println("3. 16 clientes concurrentes");
            System.out.println("4. 32 clientes concurrentes");
            System.out.println("5. 64 clientes concurrentes");
            
            int escenario = 1;
            try {
                escenario = Integer.parseInt(scanner.nextLine().trim());
                if (escenario < 1 || escenario > 5) {
                    System.out.println("Escenario no válido. Usando escenario 1.");
                    escenario = 1;
                }
            } catch (NumberFormatException e) {
                System.out.println("Entrada inválida. Usando escenario 1.");
            }
            
            switch (escenario) {
                case 1:
                    ejecutarEscenarioAutomatico(1, 32);
                    break;
                case 2:
                    ejecutarEscenarioAutomatico(4, 1);
                    break;
                case 3:
                    ejecutarEscenarioAutomatico(16, 1);
                    break;
                case 4:
                    ejecutarEscenarioAutomatico(32, 1);
                    break;
                case 5:
                    ejecutarEscenarioAutomatico(64, 1);
                    break;
            }
        } else {
            // Modo manual original
            System.out.print("Ingrese el número de clientes (1 para modo iterativo): ");
            int numClientes = 1;
            
            try {
                numClientes = scanner.nextInt();
                if (numClientes < 1) {
                    System.out.println("El número de clientes debe ser al menos 1. Usando 1 cliente.");
                    numClientes = 1;
                }
            } catch (InputMismatchException e) {
                System.out.println("Entrada inválida. Usando 1 cliente por defecto.");
                scanner.nextLine(); // Limpiar buffer
            }
            
            int numConsultas = 1;
            if (numClientes == 1) {
                System.out.print("Ingrese el número de consultas a realizar: ");
                try {
                    numConsultas = scanner.nextInt();
                    if (numConsultas < 1) {
                        System.out.println("El número de consultas debe ser al menos 1. Usando 1 consulta.");
                        numConsultas = 1;
                    }
                } catch (InputMismatchException e) {
                    System.out.println("Entrada inválida. Usando 1 consulta por defecto.");
                }
            }
            
            ejecutarEscenarioManual(numClientes, numConsultas);
        }
    }
    
    private static void ejecutarEscenarioAutomatico(int numClientes, int numConsultas) {
        System.out.println("Iniciando escenario automático con " + numClientes + " clientes y " + 
                          (numClientes == 1 ? numConsultas + " consultas" : "1 consulta cada uno"));
        
        // Para escenario de un solo cliente iterativo
        if (numClientes == 1) {
            System.out.println("\n=== INICIANDO " + numConsultas + " CONSULTAS AUTOMÁTICAS ===");
            
            // Preguntar si desea seleccionar un servicio fijo para todas las consultas
            Scanner scanner = new Scanner(System.in);
            System.out.println("¿Desea usar un servicio fijo para todas las consultas? (S/N)");
            boolean servicioFijo = scanner.nextLine().trim().toUpperCase().equals("S");
            
            String idServicioFijo = null;
            if (servicioFijo) {
                System.out.println("Seleccione el servicio a utilizar (1-3):");
                try {
                    idServicioFijo = scanner.nextLine().trim();
                    int id = Integer.parseInt(idServicioFijo);
                    if (id < 1 || id > 3) {
                        System.out.println("ID de servicio inválido. Se usará selección aleatoria.");
                        idServicioFijo = null;
                    }
                } catch (NumberFormatException e) {
                    System.out.println("Entrada inválida. Se usará selección aleatoria.");
                    idServicioFijo = null;
                }
            }
            
            for (int i = 0; i < numConsultas; i++) {
                System.out.println("\n--- Consulta " + (i+1) + " de " + numConsultas + " ---");
                // Usar servicio fijo o generar uno aleatorio
                String idServicio = servicioFijo ? idServicioFijo : generarConsultaAleatoria();
                realizarConsulta(idServicio);
                
                // Pequeña pausa para evitar sobrecarga
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            
            // Mostrar estadísticas después de todas las consultas
            mostrarEstadisticas();
        } 
        // Para escenarios concurrentes
        else {
            System.out.println("\n=== IMPORTANTE: Asegúrate de que el servidor tenga " + numClientes + " delegados configurados ===");
            System.out.println("Presiona Enter para continuar o Ctrl+C para cancelar...");
            new Scanner(System.in).nextLine();
            
            ExecutorService executor = Executors.newFixedThreadPool(numClientes);
            CountDownLatch latch = new CountDownLatch(numClientes);
            AtomicInteger conexionesExitosas = new AtomicInteger(0);
            
            for (int i = 0; i < numClientes; i++) {
                final int clienteId = i + 1;
                executor.submit(() -> {
                    try {
                        System.out.println("Cliente " + clienteId + " iniciando consulta...");
                        realizarConsulta(generarConsultaAleatoria());
                        conexionesExitosas.incrementAndGet();
                    } catch (Exception e) {
                        System.err.println("Error en cliente " + clienteId + ": " + e.getMessage());
                    } finally {
                        latch.countDown();
                    }
                });
                
                // Pequeña pausa para evitar congestión en la conexión inicial
                try {
                    Thread.sleep(10);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            
            try {
                // Esperar a que todos los clientes terminen o hasta 2 minutos máximo
                boolean completado = latch.await(2, TimeUnit.MINUTES);
                executor.shutdownNow();
                
                System.out.println("\n=== RESUMEN DE EJECUCIÓN ===");
                System.out.println("Clientes totales: " + numClientes);
                System.out.println("Conexiones exitosas: " + conexionesExitosas.get());
                System.out.println("Conexiones fallidas: " + (numClientes - conexionesExitosas.get()));
                
                if (!completado) {
                    System.out.println("ADVERTENCIA: No todas las conexiones terminaron dentro del tiempo límite.");
                }
                
                // Mostrar estadísticas
                mostrarEstadisticas();
            } catch (InterruptedException e) {
                System.err.println("Tiempo de espera agotado: " + e.getMessage());
                executor.shutdownNow();
            }
        }
    }
    
    private static void ejecutarEscenarioManual(int numClientes, int numConsultas) {
        System.out.println("Iniciando " + numClientes + " clientes con " + 
                          (numClientes == 1 ? numConsultas + " consultas" : "1 consulta cada uno"));
        
        // Para escenario de un solo cliente iterativo
        if (numClientes == 1) {
            for (int i = 0; i < numConsultas; i++) {
                System.out.println("\n--- Consulta " + (i+1) + " de " + numConsultas + " ---");
                realizarConsulta(null); // null para solicitar entrada manual
            }
            
            // Mostrar estadísticas después de todas las consultas
            mostrarEstadisticas();
        } 
        // Para escenarios concurrentes
        else {
            System.out.println("\n=== IMPORTANTE: Asegúrate de que el servidor tenga " + numClientes + " delegados configurados ===");
            System.out.println("Presiona Enter para continuar o Ctrl+C para cancelar...");
            new Scanner(System.in).nextLine();
            
            ExecutorService executor = Executors.newFixedThreadPool(numClientes);
            CountDownLatch latch = new CountDownLatch(numClientes);
            AtomicInteger conexionesExitosas = new AtomicInteger(0);
            
            for (int i = 0; i < numClientes; i++) {
                final int clienteId = i + 1;
                executor.submit(() -> {
                    try {
                        System.out.println("Cliente " + clienteId + " iniciando consulta...");
                        realizarConsulta(generarConsultaAleatoria());
                        conexionesExitosas.incrementAndGet();
                    } catch (Exception e) {
                        System.err.println("Error en cliente " + clienteId + ": " + e.getMessage());
                    } finally {
                        latch.countDown();
                    }
                });
                
                // Pequeña pausa para evitar congestión en la conexión inicial
                try {
                    Thread.sleep(10);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            
            try {
                // Esperar a que todos los clientes terminen o hasta 2 minutos máximo
                boolean completado = latch.await(2, TimeUnit.MINUTES);
                executor.shutdownNow();
                
                System.out.println("\n=== RESUMEN DE EJECUCIÓN ===");
                System.out.println("Clientes totales: " + numClientes);
                System.out.println("Conexiones exitosas: " + conexionesExitosas.get());
                System.out.println("Conexiones fallidas: " + (numClientes - conexionesExitosas.get()));
                
                if (!completado) {
                    System.out.println("ADVERTENCIA: No todas las conexiones terminaron dentro del tiempo límite.");
                }
                
                // Mostrar estadísticas
                mostrarEstadisticas();
            } catch (InterruptedException e) {
                System.err.println("Tiempo de espera agotado: " + e.getMessage());
                executor.shutdownNow();
            }
        }
    }
    
    private static void mostrarEstadisticas() {
        System.out.println("\n--- ESTADÍSTICAS DEL CLIENTE ---");
        
        System.out.println("Tiempos de conexión (ms): " + calcularEstadisticas(tiempos.get("conexion")));
        System.out.println("Tiempos de descifrado (ms): " + calcularEstadisticas(tiempos.get("descifrado")));
        System.out.println("Tiempos de verificación (ms): " + calcularEstadisticas(tiempos.get("verificacion")));
        
        // Exportar estadísticas a CSV
        exportarEstadisticasCSV();
    }
    
    private static void exportarEstadisticasCSV() {
        try {
            String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
            String filename = "estadisticas_" + timestamp + ".csv";
            
            try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
                writer.println("Tipo,Tiempo (ms)");
                
                // Escribir tiempos de conexión
                for (Long tiempo : tiempos.get("conexion")) {
                    writer.println("conexion," + tiempo);
                }
                
                // Escribir tiempos de descifrado
                for (Long tiempo : tiempos.get("descifrado")) {
                    writer.println("descifrado," + tiempo);
                }
                
                // Escribir tiempos de verificación
                for (Long tiempo : tiempos.get("verificacion")) {
                    writer.println("verificacion," + tiempo);
                }
            }
            
            System.out.println("Estadísticas exportadas a: " + filename);
        } catch (IOException e) {
            System.err.println("Error al exportar estadísticas: " + e.getMessage());
        }
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
    
    private static String generarConsultaAleatoria() {
        // Generar un ID de servicio aleatorio entre 1 y 3
        return String.valueOf(new Random().nextInt(3) + 1);
    }

    private static void realizarConsulta(String idServicio) {
        long tiempoInicioConexion = System.nanoTime();
        
        try (Socket socket = new Socket(HOST, PUERTO)) {
            System.out.println("Conectado al servidor.");
            long tiempoFinConexion = System.nanoTime();
            tiempos.get("conexion").add((tiempoFinConexion - tiempoInicioConexion) / 1_000_000);

            // Cargar clave pública del servidor para verificar firma
            PublicKey publicKeyRSA = cargarClavePublica(CLAVE_PUBLICA_SERVIDOR_PATH);
            
            // Establecimiento de sesión con Diffie-Hellman
            // 1. Generar par de claves DH para el cliente
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(1024);
            KeyPair keyPair = keyGen.generateKeyPair();
            
            // 2. Enviar clave pública DH al servidor
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            oos.writeObject(keyPair.getPublic());
            oos.flush();
            System.out.println("Clave pública DH enviada al servidor.");
            
            // 3. Recibir clave pública DH del servidor
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            PublicKey publicKeyServidor = (PublicKey) ois.readObject();
            System.out.println("Clave pública DH recibida del servidor.");
            
            // 4. Generar llave maestra
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(keyPair.getPrivate());
            keyAgreement.doPhase(publicKeyServidor, true);
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
            
            // Recibir tabla de servicios cifrada
            DataInputStream dis = new DataInputStream(socket.getInputStream());
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
            
            // Leer IV
            byte[] iv = new byte[16];
            dis.readFully(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            
            // Leer tabla cifrada
            int longitudTabla = dis.readInt();
            byte[] tablaCifrada = new byte[longitudTabla];
            dis.readFully(tablaCifrada);
            
            // Leer firma
            int longitudFirma = dis.readInt();
            byte[] firma = new byte[longitudFirma];
            dis.readFully(firma);
            
            // Leer HMAC
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(hmacKey);
            byte[] hmacRecibido = new byte[mac.getMacLength()];
            dis.readFully(hmacRecibido);
            
            // Verificar HMAC
            long tiempoInicioVerificacion = System.nanoTime();
            byte[] hmacCalculado = mac.doFinal(tablaCifrada);
            boolean hmacValido = Arrays.equals(hmacRecibido, hmacCalculado);
            long tiempoFinVerificacion = System.nanoTime();
            tiempos.get("verificacion").add((tiempoFinVerificacion - tiempoInicioVerificacion) / 1_000_000);
            
            if (!hmacValido) {
                System.out.println("Error: HMAC no coincide");
                return;
            }
            
            // Descifrar tabla
            long tiempoInicioDescifrado = System.nanoTime();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
            byte[] tablaDescifrada = cipher.doFinal(tablaCifrada);
            long tiempoFinDescifrado = System.nanoTime();
            tiempos.get("descifrado").add((tiempoFinDescifrado - tiempoInicioDescifrado) / 1_000_000);
            
            // Verificar firma
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKeyRSA);
            signature.update(tablaDescifrada);
            boolean firmaValida = signature.verify(firma);
            
            if (!firmaValida) {
                System.out.println("Error: Firma no válida");
                return;
            }
            
            // Mostrar tabla de servicios
            String tablaServicios = new String(tablaDescifrada);
            System.out.println("\nServicios disponibles:");
            System.out.println(tablaServicios);
            
            // Si no se proporcionó un ID de servicio, solicitar al usuario
            if (idServicio == null || idServicio.isEmpty()) {
                Scanner scanner = new Scanner(System.in);
                System.out.print("\nSeleccione un servicio (ingrese el ID): ");
                idServicio = scanner.nextLine();
            } else {
                System.out.println("\nServicio seleccionado automáticamente: " + idServicio);
            }
            
            // Enviar consulta cifrada
            // Generar IV aleatorio
            byte[] ivConsulta = new byte[16];
            new SecureRandom().nextBytes(ivConsulta);
            
            // Cifrar consulta
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(ivConsulta));
            byte[] consultaCifrada = cipher.doFinal(idServicio.getBytes());
            
            // Enviar IV y consulta cifrada
            dos.write(ivConsulta);
            dos.writeInt(consultaCifrada.length);
            dos.write(consultaCifrada);
            
            // Calcular y enviar HMAC de la consulta
            byte[] hmacConsulta = mac.doFinal(consultaCifrada);
            dos.write(hmacConsulta);
            System.out.println("Consulta enviada al servidor.");
            
            // Recibir respuesta cifrada
            byte[] ivRespuesta = new byte[16];
            dis.readFully(ivRespuesta);
            int longitudRespuesta = dis.readInt();
            byte[] respuestaCifrada = new byte[longitudRespuesta];
            dis.readFully(respuestaCifrada);
            
            // Leer HMAC de la respuesta
            byte[] hmacRespuesta = new byte[mac.getMacLength()];
            dis.readFully(hmacRespuesta);
            
            // Verificar HMAC de la respuesta
            byte[] hmacRespuestaCalculado = mac.doFinal(respuestaCifrada);
            if (!Arrays.equals(hmacRespuesta, hmacRespuestaCalculado)) {
                System.out.println("Error: HMAC de la respuesta no coincide");
                return;
            }
            
            // Descifrar respuesta
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(ivRespuesta));
            byte[] respuestaDescifrada = cipher.doFinal(respuestaCifrada);
            String respuesta = new String(respuestaDescifrada);
            
            // Procesar respuesta
            String[] partes = respuesta.split("\\|");
            if (partes.length >= 2 && !partes[0].equals("-1")) {
                System.out.println("Respuesta recibida:");
                System.out.println("Servicio: " + partes[0]);
                System.out.println("IP: " + partes[1]);
                System.out.println("Puerto: " + partes[2]);
            } else {
                System.out.println("Servicio no encontrado.");
            }

        } catch (ConnectException e) {
            System.err.println("Error al conectar con el servidor: " + e.getMessage());
        } catch (SocketException e) {
            System.err.println("Error de conexión: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Error en la consulta: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static PublicKey cargarClavePublica(String ruta) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(ruta));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }
}
