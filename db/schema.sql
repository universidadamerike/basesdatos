-- ============================================================
-- Base de datos: tienda_vulnerable
-- Propósito: Entorno DIDÁCTICO para una clase de ciberseguridad
--            sobre inyección SQL. NO USAR EN PRODUCCIÓN.
-- ============================================================

DROP DATABASE IF EXISTS tienda_vulnerable;
CREATE DATABASE tienda_vulnerable CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE tienda_vulnerable;

-- ------------------------------------------------------------
-- Tabla de usuarios (login del sistema / empleados)
-- ------------------------------------------------------------
CREATE TABLE usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre_usuario VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(100) NOT NULL, -- Guardada en texto plano a propósito (mala práctica didáctica)
    nombre_completo VARCHAR(100) NOT NULL,
    rol VARCHAR(20) NOT NULL DEFAULT 'empleado',
    email VARCHAR(100),
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ------------------------------------------------------------
-- Tabla de clientes de la tienda departamental
-- ------------------------------------------------------------
CREATE TABLE clientes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL,
    apellido VARCHAR(100) NOT NULL,
    email VARCHAR(100),
    telefono VARCHAR(20),
    direccion VARCHAR(200),
    ciudad VARCHAR(50),
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ------------------------------------------------------------
-- Tabla de categorías de productos
-- ------------------------------------------------------------
CREATE TABLE categorias (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(60) NOT NULL,
    descripcion VARCHAR(200)
);

-- ------------------------------------------------------------
-- Tabla de productos
-- ------------------------------------------------------------
CREATE TABLE productos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(150) NOT NULL,
    descripcion VARCHAR(300),
    precio DECIMAL(10,2) NOT NULL,
    stock INT NOT NULL DEFAULT 0,
    categoria_id INT,
    proveedor VARCHAR(100),
    FOREIGN KEY (categoria_id) REFERENCES categorias(id)
);

-- ------------------------------------------------------------
-- Tabla de ventas
-- ------------------------------------------------------------
CREATE TABLE ventas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cliente_id INT,
    usuario_id INT,
    fecha_venta TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total DECIMAL(10,2) NOT NULL DEFAULT 0,
    metodo_pago VARCHAR(30),
    FOREIGN KEY (cliente_id) REFERENCES clientes(id),
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
);

-- ------------------------------------------------------------
-- Tabla de detalle de ventas
-- ------------------------------------------------------------
CREATE TABLE detalle_ventas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    venta_id INT,
    producto_id INT,
    cantidad INT NOT NULL,
    precio_unitario DECIMAL(10,2) NOT NULL,
    FOREIGN KEY (venta_id) REFERENCES ventas(id),
    FOREIGN KEY (producto_id) REFERENCES productos(id)
);

-- ============================================================
-- DATOS DE EJEMPLO
-- ============================================================

-- Usuarios del sistema (login) - incluye un admin "secreto" para
-- que los alumnos lo descubran mediante inyección SQL.
INSERT INTO usuarios (nombre_usuario, password, nombre_completo, rol, email) VALUES
('admin', 'Admin#2024!', 'Administrador General', 'administrador', 'admin@tiendadepto.com'),
('gerente1', 'Gerente123', 'Laura Jiménez', 'gerente', 'laura.jimenez@tiendadepto.com'),
('cajero1', 'Cajero2024', 'Carlos Pérez', 'empleado', 'carlos.perez@tiendadepto.com'),
('cajero2', 'Clave_Cajero2', 'Marta Soto', 'empleado', 'marta.soto@tiendadepto.com'),
('auditor', 'S3cr3t0Aud!t', 'Roberto Núñez', 'auditor', 'roberto.nunez@tiendadepto.com');

-- Clientes
INSERT INTO clientes (nombre, apellido, email, telefono, direccion, ciudad) VALUES
('Ana', 'García', 'ana.garcia@mail.com', '8888-1234', 'Av. Central 123', 'Tegucigalpa'),
('Luis', 'Martínez', 'luis.martinez@mail.com', '8888-5678', 'Col. Kennedy, Calle 5', 'Tegucigalpa'),
('María', 'Rodríguez', 'maria.rodriguez@mail.com', '9999-1111', 'Barrio Río Piedras 45', 'San Pedro Sula'),
('José', 'Hernández', 'jose.hernandez@mail.com', '9999-2222', 'Res. Las Palmas 78', 'San Pedro Sula'),
('Carmen', 'López', 'carmen.lopez@mail.com', '8888-3333', 'Col. Miraflores 12', 'La Ceiba'),
('Pedro', 'Sánchez', 'pedro.sanchez@mail.com', '8888-4444', 'Barrio El Centro', 'Comayagua'),
('Sofía', 'Flores', 'sofia.flores@mail.com', '9999-5555', 'Res. Los Pinos 34', 'Tegucigalpa');

-- Categorías
INSERT INTO categorias (nombre, descripcion) VALUES
('Electrónica', 'Dispositivos y accesorios electrónicos'),
('Ropa', 'Ropa para dama, caballero y niños'),
('Hogar', 'Artículos para el hogar y decoración'),
('Juguetería', 'Juguetes y artículos infantiles'),
('Deportes', 'Artículos deportivos y recreativos');

-- Productos
INSERT INTO productos (nombre, descripcion, precio, stock, categoria_id, proveedor) VALUES
('Televisor LED 50"', 'Smart TV 4K UHD', 12999.00, 15, 1, 'Electro Import'),
('Laptop Core i5', 'Laptop 8GB RAM, 256GB SSD', 15999.00, 10, 1, 'TechSupply'),
('Audífonos Bluetooth', 'Audífonos inalámbricos con cancelación de ruido', 899.00, 50, 1, 'Electro Import'),
('Camisa Casual Hombre', 'Camisa manga larga 100% algodón', 450.00, 80, 2, 'Moda Express'),
('Vestido de Verano', 'Vestido ligero para dama', 650.00, 40, 2, 'Moda Express'),
('Juego de Sábanas', 'Juego de sábanas matrimonial', 780.00, 25, 3, 'Hogar Total'),
('Licuadora 3 Velocidades', 'Licuadora de uso doméstico', 1200.00, 20, 3, 'Hogar Total'),
('Muñeca Interactiva', 'Muñeca con sonido y luces', 550.00, 35, 4, 'Juguetes del Valle'),
('Balón de Fútbol', 'Balón oficial talla 5', 380.00, 60, 5, 'Deportes HN'),
('Bicicleta Montaña', 'Bicicleta rodado 26"', 4500.00, 12, 5, 'Deportes HN');

-- Ventas de ejemplo
INSERT INTO ventas (cliente_id, usuario_id, total, metodo_pago) VALUES
(1, 3, 13898.00, 'Tarjeta'),
(2, 3, 1130.00, 'Efectivo'),
(3, 4, 4500.00, 'Tarjeta'),
(4, 4, 930.00, 'Efectivo'),
(5, 3, 780.00, 'Transferencia');

-- Detalle de ventas
INSERT INTO detalle_ventas (venta_id, producto_id, cantidad, precio_unitario) VALUES
(1, 1, 1, 12999.00),
(1, 3, 1, 899.00),
(2, 4, 1, 450.00),
(2, 9, 2, 380.00),
(3, 10, 1, 4500.00),
(4, 5, 1, 650.00),
(4, 9, 1, 380.00),
(5, 6, 1, 780.00);
