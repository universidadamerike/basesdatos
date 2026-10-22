-- ============================================================
-- Script: scriptbdtienda.sql
-- Propósito: Replicar exactamente la base de datos
--            "tienda_vulnerable" (estructura + datos actuales)
--            usada en el proyecto de demostración de SQL
--            Injection para la clase de Seguridad en Bases de
--            Datos.
--
-- Generado a partir de un volcado (mysqldump) del servidor de
-- pruebas MySQL 8.0.46 en el estado actual del proyecto.
--
-- Uso:
--   mysql -h 127.0.0.1 -u root -p < scriptbdtienda.sql
--
-- ADVERTENCIA: este script elimina (DROP) la base de datos
-- "tienda_vulnerable" si ya existe antes de volver a crearla.
-- ============================================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;
SET UNIQUE_CHECKS = 0;
SET SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO';

DROP DATABASE IF EXISTS `tienda_vulnerable`;
CREATE DATABASE `tienda_vulnerable` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `tienda_vulnerable`;

-- ------------------------------------------------------------
-- Tabla: usuarios (login del sistema / empleados)
-- ------------------------------------------------------------
DROP TABLE IF EXISTS `usuarios`;
CREATE TABLE `usuarios` (
  `id` int NOT NULL AUTO_INCREMENT,
  `nombre_usuario` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL,
  `password` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `nombre_completo` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `rol` varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'empleado',
  `email` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `fecha_creacion` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `nombre_usuario` (`nombre_usuario`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `usuarios` (`id`,`nombre_usuario`,`password`,`nombre_completo`,`rol`,`email`,`fecha_creacion`) VALUES
(1,'admin','Admin#2024!','Administrador General','administrador','admin@tiendadepto.com','2026-10-21 16:01:18'),
(2,'gerente1','Gerente123','Laura Jiménez','gerente','laura.jimenez@tiendadepto.com','2026-10-21 16:01:18'),
(3,'cajero1','Cajero2024','Carlos Pérez','empleado','carlos.perez@tiendadepto.com','2026-10-21 16:01:18'),
(4,'cajero2','Clave_Cajero2','Marta Soto','empleado','marta.soto@tiendadepto.com','2026-10-21 16:01:18'),
(5,'auditor','S3cr3t0Aud!t','Roberto Núñez','auditor','roberto.nunez@tiendadepto.com','2026-10-21 16:01:18');

-- ------------------------------------------------------------
-- Tabla: clientes
-- ------------------------------------------------------------
DROP TABLE IF EXISTS `clientes`;
CREATE TABLE `clientes` (
  `id` int NOT NULL AUTO_INCREMENT,
  `nombre` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `apellido` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `email` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `telefono` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `direccion` varchar(200) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `ciudad` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `fecha_registro` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `clientes` (`id`,`nombre`,`apellido`,`email`,`telefono`,`direccion`,`ciudad`,`fecha_registro`) VALUES
(1,'Ana','García','ana.garcia@mail.com','8888-1234','Av. Central 123','Tegucigalpa','2026-10-21 16:01:18'),
(2,'Luis','Martínez','luis.martinez@mail.com','8888-5678','Col. Kennedy, Calle 5','Tegucigalpa','2026-10-21 16:01:18'),
(3,'María','Rodríguez','maria.rodriguez@mail.com','9999-1111','Barrio Río Piedras 45','San Pedro Sula','2026-10-21 16:01:18'),
(4,'José','Hernández','jose.hernandez@mail.com','9999-2222','Res. Las Palmas 78','San Pedro Sula','2026-10-21 16:01:18'),
(5,'Carmen','López','carmen.lopez@mail.com','8888-3333','Col. Miraflores 12','La Ceiba','2026-10-21 16:01:18'),
(6,'Pedro','Sánchez','pedro.sanchez@mail.com','8888-4444','Barrio El Centro','Comayagua','2026-10-21 16:01:18'),
(7,'Sofía','Flores','sofia.flores@mail.com','9999-5555','Res. Los Pinos 34','Tegucigalpa','2026-10-21 16:01:18');

-- ------------------------------------------------------------
-- Tabla: categorias
-- ------------------------------------------------------------
DROP TABLE IF EXISTS `categorias`;
CREATE TABLE `categorias` (
  `id` int NOT NULL AUTO_INCREMENT,
  `nombre` varchar(60) COLLATE utf8mb4_unicode_ci NOT NULL,
  `descripcion` varchar(200) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `categorias` (`id`,`nombre`,`descripcion`) VALUES
(1,'Electrónica','Dispositivos y accesorios electrónicos'),
(2,'Ropa','Ropa para dama, caballero y niños'),
(3,'Hogar','Artículos para el hogar y decoración'),
(4,'Juguetería','Juguetes y artículos infantiles'),
(5,'Deportes','Artículos deportivos y recreativos');

-- ------------------------------------------------------------
-- Tabla: productos
-- ------------------------------------------------------------
DROP TABLE IF EXISTS `productos`;
CREATE TABLE `productos` (
  `id` int NOT NULL AUTO_INCREMENT,
  `nombre` varchar(150) COLLATE utf8mb4_unicode_ci NOT NULL,
  `descripcion` varchar(300) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `precio` decimal(10,2) NOT NULL,
  `stock` int NOT NULL DEFAULT '0',
  `categoria_id` int DEFAULT NULL,
  `proveedor` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `categoria_id` (`categoria_id`),
  CONSTRAINT `productos_ibfk_1` FOREIGN KEY (`categoria_id`) REFERENCES `categorias` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `productos` (`id`,`nombre`,`descripcion`,`precio`,`stock`,`categoria_id`,`proveedor`) VALUES
(1,'Televisor LED 50\"','Smart TV 4K UHD',12999.00,15,1,'Electro Import'),
(2,'Laptop Core i5','Laptop 8GB RAM, 256GB SSD',15999.00,10,1,'TechSupply'),
(3,'Audífonos Bluetooth','Audífonos inalámbricos con cancelación de ruido',899.00,50,1,'Electro Import'),
(4,'Camisa Casual Hombre','Camisa manga larga 100% algodón',450.00,80,2,'Moda Express'),
(5,'Vestido de Verano','Vestido ligero para dama',650.00,40,2,'Moda Express'),
(6,'Juego de Sábanas','Juego de sábanas matrimonial',780.00,25,3,'Hogar Total'),
(7,'Licuadora 3 Velocidades','Licuadora de uso doméstico',1200.00,20,3,'Hogar Total'),
(8,'Muñeca Interactiva','Muñeca con sonido y luces',550.00,35,4,'Juguetes del Valle'),
(9,'Balón de Fútbol','Balón oficial talla 5',380.00,60,5,'Deportes HN'),
(10,'Bicicleta Montaña','Bicicleta rodado 26\"',4500.00,12,5,'Deportes HN');

-- ------------------------------------------------------------
-- Tabla: ventas
-- ------------------------------------------------------------
DROP TABLE IF EXISTS `ventas`;
CREATE TABLE `ventas` (
  `id` int NOT NULL AUTO_INCREMENT,
  `cliente_id` int DEFAULT NULL,
  `usuario_id` int DEFAULT NULL,
  `fecha_venta` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `total` decimal(10,2) NOT NULL DEFAULT '0.00',
  `metodo_pago` varchar(30) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `cliente_id` (`cliente_id`),
  KEY `usuario_id` (`usuario_id`),
  CONSTRAINT `ventas_ibfk_1` FOREIGN KEY (`cliente_id`) REFERENCES `clientes` (`id`),
  CONSTRAINT `ventas_ibfk_2` FOREIGN KEY (`usuario_id`) REFERENCES `usuarios` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `ventas` (`id`,`cliente_id`,`usuario_id`,`fecha_venta`,`total`,`metodo_pago`) VALUES
(1,1,3,'2026-10-21 16:01:18',13898.00,'Tarjeta'),
(2,2,3,'2026-10-21 16:01:18',1130.00,'Efectivo'),
(3,3,4,'2026-10-21 16:01:18',4500.00,'Tarjeta'),
(4,4,4,'2026-10-21 16:01:18',930.00,'Efectivo'),
(5,5,3,'2026-10-21 16:01:18',780.00,'Transferencia');

-- ------------------------------------------------------------
-- Tabla: detalle_ventas
-- ------------------------------------------------------------
DROP TABLE IF EXISTS `detalle_ventas`;
CREATE TABLE `detalle_ventas` (
  `id` int NOT NULL AUTO_INCREMENT,
  `venta_id` int DEFAULT NULL,
  `producto_id` int DEFAULT NULL,
  `cantidad` int NOT NULL,
  `precio_unitario` decimal(10,2) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `venta_id` (`venta_id`),
  KEY `producto_id` (`producto_id`),
  CONSTRAINT `detalle_ventas_ibfk_1` FOREIGN KEY (`venta_id`) REFERENCES `ventas` (`id`),
  CONSTRAINT `detalle_ventas_ibfk_2` FOREIGN KEY (`producto_id`) REFERENCES `productos` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `detalle_ventas` (`id`,`venta_id`,`producto_id`,`cantidad`,`precio_unitario`) VALUES
(1,1,1,1,12999.00),
(2,1,3,1,899.00),
(3,2,4,1,450.00),
(4,2,9,2,380.00),
(5,3,10,1,4500.00),
(6,4,5,1,650.00),
(7,4,9,1,380.00),
(8,5,6,1,780.00);

SET FOREIGN_KEY_CHECKS = 1;
SET UNIQUE_CHECKS = 1;

-- ============================================================
-- Fin del script. La base de datos "tienda_vulnerable" queda
-- lista con la misma estructura y los mismos datos que tiene
-- actualmente el entorno de la clase (5 usuarios, 7 clientes,
-- 5 categorías, 10 productos, 5 ventas, 8 líneas de detalle).
-- ============================================================
