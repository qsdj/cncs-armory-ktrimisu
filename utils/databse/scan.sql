-- MySQL dump 10.13  Distrib 5.7.20, for Linux (x86_64)
--
-- Host: localhost    Database: scan
-- ------------------------------------------------------
-- Server version	5.7.20-0ubuntu0.16.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Current Database: `scan`
--

CREATE DATABASE /*!32312 IF NOT EXISTS*/ `scan` /*!40100 DEFAULT CHARACTER SET utf8 */;

USE `scan`;

--
-- Table structure for table `auth_group`
--

DROP TABLE IF EXISTS `auth_group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_group` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(80) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_group`
--

LOCK TABLES `auth_group` WRITE;
/*!40000 ALTER TABLE `auth_group` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_group` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_group_permissions`
--

DROP TABLE IF EXISTS `auth_group_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_group_permissions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `group_id` int(11) NOT NULL,
  `permission_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_group_permissions_group_id_permission_id_0cd325b0_uniq` (`group_id`,`permission_id`),
  KEY `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` (`permission_id`),
  CONSTRAINT `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  CONSTRAINT `auth_group_permissions_group_id_b120cbf9_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_group_permissions`
--

LOCK TABLES `auth_group_permissions` WRITE;
/*!40000 ALTER TABLE `auth_group_permissions` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_group_permissions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_permission`
--

DROP TABLE IF EXISTS `auth_permission`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_permission` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `content_type_id` int(11) NOT NULL,
  `codename` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_permission_content_type_id_codename_01ab375a_uniq` (`content_type_id`,`codename`),
  CONSTRAINT `auth_permission_content_type_id_2f476e4b_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=49 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_permission`
--

LOCK TABLES `auth_permission` WRITE;
/*!40000 ALTER TABLE `auth_permission` DISABLE KEYS */;
INSERT INTO `auth_permission` VALUES (1,'Can add group',1,'add_group'),(2,'Can change group',1,'change_group'),(3,'Can delete group',1,'delete_group'),(4,'Can add permission',2,'add_permission'),(5,'Can change permission',2,'change_permission'),(6,'Can delete permission',2,'delete_permission'),(7,'Can add content type',3,'add_contenttype'),(8,'Can change content type',3,'change_contenttype'),(9,'Can delete content type',3,'delete_contenttype'),(10,'Can add project poc',4,'add_projectpoc'),(11,'Can change project poc',4,'change_projectpoc'),(12,'Can delete project poc',4,'delete_projectpoc'),(13,'Can add user',5,'add_user'),(14,'Can change user',5,'change_user'),(15,'Can delete user',5,'delete_user'),(16,'Can add project',6,'add_project'),(17,'Can change project',6,'change_project'),(18,'Can delete project',6,'delete_project'),(19,'Can add poc',7,'add_poc'),(20,'Can change poc',7,'change_poc'),(21,'Can delete poc',7,'delete_poc'),(22,'Can add session',8,'add_session'),(23,'Can change session',8,'change_session'),(24,'Can delete session',8,'delete_session'),(25,'Can add periodic task',9,'add_periodictask'),(26,'Can change periodic task',9,'change_periodictask'),(27,'Can delete periodic task',9,'delete_periodictask'),(28,'Can add crontab',10,'add_crontabschedule'),(29,'Can change crontab',10,'change_crontabschedule'),(30,'Can delete crontab',10,'delete_crontabschedule'),(31,'Can add interval',11,'add_intervalschedule'),(32,'Can change interval',11,'change_intervalschedule'),(33,'Can delete interval',11,'delete_intervalschedule'),(34,'Can add periodic tasks',12,'add_periodictasks'),(35,'Can change periodic tasks',12,'change_periodictasks'),(36,'Can delete periodic tasks',12,'delete_periodictasks'),(37,'Can add task state',13,'add_taskmeta'),(38,'Can change task state',13,'change_taskmeta'),(39,'Can delete task state',13,'delete_taskmeta'),(40,'Can add saved group result',14,'add_tasksetmeta'),(41,'Can change saved group result',14,'change_tasksetmeta'),(42,'Can delete saved group result',14,'delete_tasksetmeta'),(43,'Can add worker',15,'add_workerstate'),(44,'Can change worker',15,'change_workerstate'),(45,'Can delete worker',15,'delete_workerstate'),(46,'Can add task',16,'add_taskstate'),(47,'Can change task',16,'change_taskstate'),(48,'Can delete task',16,'delete_taskstate');
/*!40000 ALTER TABLE `auth_permission` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `celery_taskmeta`
--

DROP TABLE IF EXISTS `celery_taskmeta`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `celery_taskmeta` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `task_id` varchar(255) NOT NULL,
  `status` varchar(50) NOT NULL,
  `result` longtext,
  `date_done` datetime(6) NOT NULL,
  `traceback` longtext,
  `hidden` tinyint(1) NOT NULL,
  `meta` longtext,
  PRIMARY KEY (`id`),
  UNIQUE KEY `task_id` (`task_id`),
  KEY `celery_taskmeta_hidden_23fd02dc` (`hidden`)
) ENGINE=InnoDB AUTO_INCREMENT=47 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `celery_taskmeta`
--

LOCK TABLES `celery_taskmeta` WRITE;
/*!40000 ALTER TABLE `celery_taskmeta` DISABLE KEYS */;
INSERT INTO `celery_taskmeta` VALUES (1,'897dc0bc-b4ee-4200-a635-f1c8b94f4f6e','SUCCESS',NULL,'2017-10-27 07:58:51.754189',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(2,'93ba4462-f42f-4040-9f40-3acdbeb0d390','SUCCESS',NULL,'2017-10-27 08:00:49.992698',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(3,'4f6a18df-8ed6-4c65-a10c-1c400ac2b52c','SUCCESS',NULL,'2017-10-27 08:00:57.581724',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(4,'4efb08e5-3f08-4472-b33a-7669cfae6145','SUCCESS',NULL,'2017-10-27 08:12:44.812874',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(5,'d948b33f-6754-4f09-8751-fbcb8e4bfcc5','SUCCESS',NULL,'2017-10-27 08:13:03.165484',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(6,'2b5c7d2e-b7e0-4e2d-996d-a61ba5bb6998','SUCCESS',NULL,'2017-10-27 08:33:10.119019',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(7,'2f75d504-512c-4797-b154-2183a39b019f','SUCCESS',NULL,'2017-10-27 08:36:39.548840',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(8,'66c8d610-6f16-4dd7-bc56-6170ed1f7a97','FAILURE','gAJ9cQEoVQtleGNfbWVzc2FnZXECVSZQcm9qZWN0IG1hdGNoaW5nIHF1ZXJ5IGRvZXMgbm90IGV4aXN0LnEDVQhleGNfdHlwZXEEVQxEb2VzTm90RXhpc3RxBXUu','2017-10-27 08:53:28.142012','Traceback (most recent call last):\n  File \"/usr/local/lib/python2.7/dist-packages/celery/app/trace.py\", line 240, in trace_task\n    R = retval = fun(*args, **kwargs)\n  File \"/usr/local/lib/python2.7/dist-packages/celery/app/trace.py\", line 438, in __protected_call__\n    return self.run(*args, **kwargs)\n  File \"/opt/TScan/TScan/tasks.py\", line 15, in run_task\n    project = models.Project.objects.get(id=url[\'id\'])\n  File \"/usr/local/lib/python2.7/dist-packages/django/db/models/manager.py\", line 85, in manager_method\n    return getattr(self.get_queryset(), name)(*args, **kwargs)\n  File \"/usr/local/lib/python2.7/dist-packages/django/db/models/query.py\", line 380, in get\n    self.model._meta.object_name\nDoesNotExist: Project matching query does not exist.\n',0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(9,'06b9a89a-cd20-46dd-9b0f-57db9e34cc17','SUCCESS',NULL,'2017-10-27 08:54:23.529820',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(10,'35a6bd9a-8719-48e0-92ee-e6556c1bd9bb','SUCCESS',NULL,'2017-10-27 08:54:36.525758',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(11,'f693c1d4-1c8b-4199-bfe0-47d324a844da','SUCCESS',NULL,'2017-10-27 09:02:17.092816',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(12,'76dcc874-2fd9-4a69-a4ca-bcf9b3671499','SUCCESS',NULL,'2017-10-27 09:04:05.545478',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(13,'a9e8ffe3-c9f8-45e5-ad33-c70797b456cf','SUCCESS',NULL,'2017-10-27 09:40:53.831860',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(14,'9f4643b6-49db-4787-8de2-392261d542cd','FAILURE','gAJ9cQEoVQtleGNfbWVzc2FnZXECVSZQcm9qZWN0IG1hdGNoaW5nIHF1ZXJ5IGRvZXMgbm90IGV4aXN0LnEDVQhleGNfdHlwZXEEVQxEb2VzTm90RXhpc3RxBXUu','2017-10-27 09:40:53.840051','Traceback (most recent call last):\n  File \"/usr/local/lib/python2.7/dist-packages/celery/app/trace.py\", line 240, in trace_task\n    R = retval = fun(*args, **kwargs)\n  File \"/usr/local/lib/python2.7/dist-packages/celery/app/trace.py\", line 438, in __protected_call__\n    return self.run(*args, **kwargs)\n  File \"/opt/TScan/TScan/tasks.py\", line 15, in run_task\n    project = models.Project.objects.get(id=url[\'id\'])\n  File \"/usr/local/lib/python2.7/dist-packages/django/db/models/manager.py\", line 85, in manager_method\n    return getattr(self.get_queryset(), name)(*args, **kwargs)\n  File \"/usr/local/lib/python2.7/dist-packages/django/db/models/query.py\", line 380, in get\n    self.model._meta.object_name\nDoesNotExist: Project matching query does not exist.\n',0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(15,'f9548658-6bff-42d3-9e0f-5d955c62bf43','SUCCESS',NULL,'2017-10-27 09:44:49.625353',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(16,'be0ba71d-5150-4a56-8215-741bab5f98c1','SUCCESS',NULL,'2017-10-30 02:00:45.617144',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(17,'e0ec5386-563a-4180-ac7b-4feaa803211d','SUCCESS',NULL,'2017-10-30 02:01:38.549555',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(18,'a04e7bb0-3831-47b6-8b12-a81819d45de2','FAILURE','gAJ9cQEoVQtleGNfbWVzc2FnZXECVSZQcm9qZWN0IG1hdGNoaW5nIHF1ZXJ5IGRvZXMgbm90IGV4aXN0LnEDVQhleGNfdHlwZXEEVQxEb2VzTm90RXhpc3RxBXUu','2017-10-30 02:36:50.532208','Traceback (most recent call last):\n  File \"/usr/local/lib/python2.7/dist-packages/celery/app/trace.py\", line 240, in trace_task\n    R = retval = fun(*args, **kwargs)\n  File \"/usr/local/lib/python2.7/dist-packages/celery/app/trace.py\", line 438, in __protected_call__\n    return self.run(*args, **kwargs)\n  File \"/opt/TScan/TScan/tasks.py\", line 15, in run_task\n    project = models.Project.objects.get(id=url[\'id\'])\n  File \"/usr/local/lib/python2.7/dist-packages/django/db/models/manager.py\", line 85, in manager_method\n    return getattr(self.get_queryset(), name)(*args, **kwargs)\n  File \"/usr/local/lib/python2.7/dist-packages/django/db/models/query.py\", line 380, in get\n    self.model._meta.object_name\nDoesNotExist: Project matching query does not exist.\n',0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(19,'ba50667d-72df-4d0b-a197-fdc2515218fe','SUCCESS',NULL,'2017-10-30 02:37:01.142471',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(20,'c6162a17-264f-4d02-a521-600b9cc32fb8','SUCCESS',NULL,'2017-10-30 02:39:26.435424',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(21,'bdbda668-2d3e-4530-a0ce-b3499d8a0331','SUCCESS',NULL,'2017-10-30 02:39:36.680470',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(22,'eeeed200-defd-4efd-92af-e98ed0f00c98','SUCCESS',NULL,'2017-10-30 02:54:28.869852',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(23,'0dcd13aa-ed71-4bb5-85fa-6625a4215363','SUCCESS',NULL,'2017-10-30 03:00:28.174404',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(24,'878ff46b-c71a-4033-848c-4c10e7662550','SUCCESS',NULL,'2017-10-30 06:53:20.123141',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(25,'6d7c210d-200d-4cac-96ac-97a9b22f7790','SUCCESS',NULL,'2017-10-30 07:24:30.960904',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(26,'bae864d8-f89a-4a1c-8d83-809918a311f2','SUCCESS',NULL,'2017-10-30 07:29:09.628189',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(27,'f8e725fb-ccb3-4a52-97ce-3779bd5052de','SUCCESS',NULL,'2017-10-31 13:41:47.148191',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(28,'a6236ebb-44b4-45df-a132-7e31adadd4bf','SUCCESS',NULL,'2017-11-17 13:11:50.849891',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(29,'821f6301-9f6c-4edc-97d5-b275d9b773c8','SUCCESS',NULL,'2017-11-20 08:30:08.896422',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(30,'b1f06d0e-805b-49cf-af95-79b18dd8f7cb','SUCCESS',NULL,'2017-11-21 05:28:12.478653',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(31,'fc7b4f8d-99b1-48d6-b200-d292827a8991','SUCCESS',NULL,'2017-11-21 05:30:41.251082',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(32,'3304ade1-61d0-4655-98c1-22c66fa39bce','SUCCESS',NULL,'2017-11-21 05:32:41.814583',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(33,'c7b54dba-4a19-4454-8ebf-7e43a1c46c3a','SUCCESS',NULL,'2017-11-21 05:37:38.793014',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(34,'8182bff5-04b8-48e0-a4d4-27865274c1db','SUCCESS',NULL,'2017-11-21 05:38:45.926381',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(35,'162add82-3280-4aea-b636-f04f5e33a602','SUCCESS',NULL,'2017-11-21 06:04:45.247505',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(36,'6e169dbe-dd46-4c82-a18f-569b0409bbe3','SUCCESS',NULL,'2017-11-21 06:10:41.667589',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(37,'4955e08a-a9e1-4e60-9bc1-1459ecef012c','SUCCESS',NULL,'2017-11-21 06:12:38.624892',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(38,'f8122364-4c35-4b3d-859a-ff79f93e2ae9','SUCCESS',NULL,'2017-11-21 07:21:09.935565',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(39,'ab2fd42e-7109-451c-8606-d615d8d9d931','SUCCESS',NULL,'2017-11-21 07:21:34.245537',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(40,'0f05d2a3-648f-48c0-a36d-33f408fc40c0','SUCCESS',NULL,'2017-11-21 07:27:05.307986',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(41,'f26c9fb3-6642-48bc-bbe0-0bd8a7a84545','SUCCESS',NULL,'2017-11-21 08:06:46.610490',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(42,'25e4f02c-dcaa-4554-8eed-973b9737861e','SUCCESS',NULL,'2017-11-21 08:56:15.498511',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(43,'7883668d-8080-4f42-b48b-4df632cb95d5','SUCCESS',NULL,'2017-11-24 03:11:45.853811',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(44,'0eff57b1-71e3-4d1e-b3be-35fa5d7716cf','SUCCESS',NULL,'2017-11-24 03:12:27.576297',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(45,'339acc2d-efde-4a76-a57c-ce3f904b176a','SUCCESS',NULL,'2017-11-24 03:30:39.181325',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA'),(46,'6600fde9-6acb-44b6-8edb-45e5d0274e4b','SUCCESS',NULL,'2018-03-09 08:47:50.284367',NULL,0,'eJxrYKotZIzgYGBgSM7IzEkpSs0rZIotZC7WAwBWuwcA');
/*!40000 ALTER TABLE `celery_taskmeta` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `celery_tasksetmeta`
--

DROP TABLE IF EXISTS `celery_tasksetmeta`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `celery_tasksetmeta` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `taskset_id` varchar(255) NOT NULL,
  `result` longtext NOT NULL,
  `date_done` datetime(6) NOT NULL,
  `hidden` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `taskset_id` (`taskset_id`),
  KEY `celery_tasksetmeta_hidden_593cfc24` (`hidden`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `celery_tasksetmeta`
--

LOCK TABLES `celery_tasksetmeta` WRITE;
/*!40000 ALTER TABLE `celery_tasksetmeta` DISABLE KEYS */;
/*!40000 ALTER TABLE `celery_tasksetmeta` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_content_type`
--

DROP TABLE IF EXISTS `django_content_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_content_type` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `app_label` varchar(100) NOT NULL,
  `model` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `django_content_type_app_label_model_76bd3d3b_uniq` (`app_label`,`model`)
) ENGINE=InnoDB AUTO_INCREMENT=17 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_content_type`
--

LOCK TABLES `django_content_type` WRITE;
/*!40000 ALTER TABLE `django_content_type` DISABLE KEYS */;
INSERT INTO `django_content_type` VALUES (1,'auth','group'),(2,'auth','permission'),(3,'contenttypes','contenttype'),(10,'djcelery','crontabschedule'),(11,'djcelery','intervalschedule'),(9,'djcelery','periodictask'),(12,'djcelery','periodictasks'),(13,'djcelery','taskmeta'),(14,'djcelery','tasksetmeta'),(16,'djcelery','taskstate'),(15,'djcelery','workerstate'),(8,'sessions','session'),(7,'TScan','poc'),(6,'TScan','project'),(4,'TScan','projectpoc'),(5,'TScan','user');
/*!40000 ALTER TABLE `django_content_type` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_migrations`
--

DROP TABLE IF EXISTS `django_migrations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_migrations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `app` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `applied` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_migrations`
--

LOCK TABLES `django_migrations` WRITE;
/*!40000 ALTER TABLE `django_migrations` DISABLE KEYS */;
INSERT INTO `django_migrations` VALUES (1,'contenttypes','0001_initial','2017-10-25 09:02:23.354016'),(2,'contenttypes','0002_remove_content_type_name','2017-10-25 09:02:23.454499'),(3,'auth','0001_initial','2017-10-25 09:02:23.767462'),(4,'auth','0002_alter_permission_name_max_length','2017-10-25 09:02:23.866361'),(5,'auth','0003_alter_user_email_max_length','2017-10-25 09:02:23.877739'),(6,'auth','0004_alter_user_username_opts','2017-10-25 09:02:23.888967'),(7,'auth','0005_alter_user_last_login_null','2017-10-25 09:02:23.901229'),(8,'auth','0006_require_contenttypes_0002','2017-10-25 09:02:23.904951'),(9,'auth','0007_alter_validators_add_error_messages','2017-10-25 09:02:23.915684'),(10,'auth','0008_alter_user_username_max_length','2017-10-25 09:02:23.932647'),(11,'TScan','0001_initial','2017-10-25 09:02:24.622157'),(12,'sessions','0001_initial','2017-10-25 09:02:30.731224'),(13,'djcelery','0001_initial','2017-10-27 07:57:55.223508');
/*!40000 ALTER TABLE `django_migrations` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_session`
--

DROP TABLE IF EXISTS `django_session`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_session` (
  `session_key` varchar(40) NOT NULL,
  `session_data` longtext NOT NULL,
  `expire_date` datetime(6) NOT NULL,
  PRIMARY KEY (`session_key`),
  KEY `django_session_expire_date_a5c62663` (`expire_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_session`
--

LOCK TABLES `django_session` WRITE;
/*!40000 ALTER TABLE `django_session` DISABLE KEYS */;
INSERT INTO `django_session` VALUES ('0bfih9jiyb0847744sz1su0s5zsbp44u','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2017-11-22 04:11:13.835490'),('0cr4d41agqza5k0tr97ylvwrlx29cgkj','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2017-12-05 06:07:31.685727'),('1tksb4n1akk5aetm0kess45gnfscypqu','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2017-11-11 10:57:02.371875'),('25a6fvkpjgdipoerd1qednz5mgxyjvly','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2017-12-05 08:47:36.437321'),('31jvp9za02561f2q24yeeoph2qjs6eyz','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2017-11-08 09:06:24.241905'),('3x88vxtnoo59pu1bfl4kmfrgqimklp1k','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2017-12-27 07:42:41.009543'),('47ccwpzy00f0isgmc883vuq9230bp7ii','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2017-11-09 01:13:49.038725'),('4toslufa8a8wpu95r541gmx5nvcqvv4f','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2017-12-08 02:17:03.555029'),('5aqmd5kwt1z5w4ilzw77sd0m9j7kucha','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2017-12-05 08:21:45.522218'),('6prib4j7i4yt85fdio0jktyncee3vnpa','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2017-12-13 06:17:23.564065'),('7n0b9qbjpgotoamc13qaxeqs5poxocwi','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2017-12-05 05:20:58.675597'),('7swz918dqkmn7zkjip41w4tyfuvnfvic','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2018-03-29 01:31:27.686898'),('864rvltbu649y6wj291ume086hosfxt7','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2018-03-30 01:15:31.390069'),('aaw6puqgznxc1v52on6ux042fsnqzwx0','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2018-03-31 13:01:25.535190'),('am7gzs6d6ytmg3ydoon80nzto89vapik','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2017-11-11 07:25:44.113961'),('ex9nryzsdfgr7zhwunxyt8188az9vxre','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2017-11-10 09:13:11.942255'),('hr0peiwumz9hc0yu8vpjb1s7d1v0imcs','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2017-11-10 08:20:17.528674'),('iqb806behh7m4pqnjg5n0bntsudrewbo','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2017-12-05 05:19:49.157606'),('jmhk20l3qghlic6vhbhllf30698zr6px','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2017-12-05 09:06:30.255657'),('k90m50x1bgj2z5nop3313dxi5i023lif','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2017-12-05 06:46:01.235228'),('lkcsfxgsoyf0ct6rrp3uud6bmulefa5g','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2017-11-13 07:29:31.177928'),('o7owylvhl4wf1chcjnihzeeie2pxzjh0','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2018-03-31 09:29:25.241357'),('qqlxopyxjj6ik21ltoe27nkjujpuqy9f','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2018-02-08 14:26:36.121125'),('si8bod68pf0woolewlue4yoxncda5x1f','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2017-12-08 03:09:36.022243'),('umv1o2mz31rk39b2o71xdx8zccwvck1h','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2017-11-13 07:25:14.631742'),('veso4ofdk8bb4yan4evadrowt5j3bbpc','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2017-12-01 13:11:03.463500'),('xf9ao5dheb5x2uvj707jjp3rg4nrfzvc','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2018-03-02 12:15:09.827167'),('zkrxkkgm5xtcwfqfscsdhc3mk7hweuci','NWZiODQxNmU0OGM1ZDQ5NmViYTY0OWFmZDAxZGFhNmE1MzE3NzQ3YTp7Il9hdXRoX3VzZXJfaGFzaCI6IjIwODMxMjkzNGQxZGE2Y2E0NGY2MmMxNWUzMjk1NmNmYTJlNmI5MjciLCJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOiIxIn0=','2018-02-10 01:04:36.090220');
/*!40000 ALTER TABLE `django_session` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `djcelery_crontabschedule`
--

DROP TABLE IF EXISTS `djcelery_crontabschedule`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `djcelery_crontabschedule` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `minute` varchar(64) NOT NULL,
  `hour` varchar(64) NOT NULL,
  `day_of_week` varchar(64) NOT NULL,
  `day_of_month` varchar(64) NOT NULL,
  `month_of_year` varchar(64) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `djcelery_crontabschedule`
--

LOCK TABLES `djcelery_crontabschedule` WRITE;
/*!40000 ALTER TABLE `djcelery_crontabschedule` DISABLE KEYS */;
/*!40000 ALTER TABLE `djcelery_crontabschedule` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `djcelery_intervalschedule`
--

DROP TABLE IF EXISTS `djcelery_intervalschedule`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `djcelery_intervalschedule` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `every` int(11) NOT NULL,
  `period` varchar(24) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `djcelery_intervalschedule`
--

LOCK TABLES `djcelery_intervalschedule` WRITE;
/*!40000 ALTER TABLE `djcelery_intervalschedule` DISABLE KEYS */;
/*!40000 ALTER TABLE `djcelery_intervalschedule` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `djcelery_periodictask`
--

DROP TABLE IF EXISTS `djcelery_periodictask`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `djcelery_periodictask` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(200) NOT NULL,
  `task` varchar(200) NOT NULL,
  `args` longtext NOT NULL,
  `kwargs` longtext NOT NULL,
  `queue` varchar(200) DEFAULT NULL,
  `exchange` varchar(200) DEFAULT NULL,
  `routing_key` varchar(200) DEFAULT NULL,
  `expires` datetime(6) DEFAULT NULL,
  `enabled` tinyint(1) NOT NULL,
  `last_run_at` datetime(6) DEFAULT NULL,
  `total_run_count` int(10) unsigned NOT NULL,
  `date_changed` datetime(6) NOT NULL,
  `description` longtext NOT NULL,
  `crontab_id` int(11) DEFAULT NULL,
  `interval_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`),
  KEY `djcelery_periodictas_crontab_id_75609bab_fk_djcelery_` (`crontab_id`),
  KEY `djcelery_periodictas_interval_id_b426ab02_fk_djcelery_` (`interval_id`),
  CONSTRAINT `djcelery_periodictas_crontab_id_75609bab_fk_djcelery_` FOREIGN KEY (`crontab_id`) REFERENCES `djcelery_crontabschedule` (`id`),
  CONSTRAINT `djcelery_periodictas_interval_id_b426ab02_fk_djcelery_` FOREIGN KEY (`interval_id`) REFERENCES `djcelery_intervalschedule` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `djcelery_periodictask`
--

LOCK TABLES `djcelery_periodictask` WRITE;
/*!40000 ALTER TABLE `djcelery_periodictask` DISABLE KEYS */;
/*!40000 ALTER TABLE `djcelery_periodictask` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `djcelery_periodictasks`
--

DROP TABLE IF EXISTS `djcelery_periodictasks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `djcelery_periodictasks` (
  `ident` smallint(6) NOT NULL,
  `last_update` datetime(6) NOT NULL,
  PRIMARY KEY (`ident`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `djcelery_periodictasks`
--

LOCK TABLES `djcelery_periodictasks` WRITE;
/*!40000 ALTER TABLE `djcelery_periodictasks` DISABLE KEYS */;
/*!40000 ALTER TABLE `djcelery_periodictasks` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `djcelery_taskstate`
--

DROP TABLE IF EXISTS `djcelery_taskstate`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `djcelery_taskstate` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `state` varchar(64) NOT NULL,
  `task_id` varchar(36) NOT NULL,
  `name` varchar(200) DEFAULT NULL,
  `tstamp` datetime(6) NOT NULL,
  `args` longtext,
  `kwargs` longtext,
  `eta` datetime(6) DEFAULT NULL,
  `expires` datetime(6) DEFAULT NULL,
  `result` longtext,
  `traceback` longtext,
  `runtime` double DEFAULT NULL,
  `retries` int(11) NOT NULL,
  `hidden` tinyint(1) NOT NULL,
  `worker_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `task_id` (`task_id`),
  KEY `djcelery_taskstate_state_53543be4` (`state`),
  KEY `djcelery_taskstate_name_8af9eded` (`name`),
  KEY `djcelery_taskstate_tstamp_4c3f93a1` (`tstamp`),
  KEY `djcelery_taskstate_hidden_c3905e57` (`hidden`),
  KEY `djcelery_taskstate_worker_id_f7f57a05_fk_djcelery_workerstate_id` (`worker_id`),
  CONSTRAINT `djcelery_taskstate_worker_id_f7f57a05_fk_djcelery_workerstate_id` FOREIGN KEY (`worker_id`) REFERENCES `djcelery_workerstate` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `djcelery_taskstate`
--

LOCK TABLES `djcelery_taskstate` WRITE;
/*!40000 ALTER TABLE `djcelery_taskstate` DISABLE KEYS */;
/*!40000 ALTER TABLE `djcelery_taskstate` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `djcelery_workerstate`
--

DROP TABLE IF EXISTS `djcelery_workerstate`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `djcelery_workerstate` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `hostname` varchar(255) NOT NULL,
  `last_heartbeat` datetime(6) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `hostname` (`hostname`),
  KEY `djcelery_workerstate_last_heartbeat_4539b544` (`last_heartbeat`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `djcelery_workerstate`
--

LOCK TABLES `djcelery_workerstate` WRITE;
/*!40000 ALTER TABLE `djcelery_workerstate` DISABLE KEYS */;
/*!40000 ALTER TABLE `djcelery_workerstate` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `poc`
--

DROP TABLE IF EXISTS `poc`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `poc` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `pid` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `product` varchar(255) NOT NULL,
  `product_version` varchar(255) NOT NULL,
  `desc` varchar(500) NOT NULL,
  `author` varchar(255) NOT NULL,
  `type` varchar(255) NOT NULL,
  `severity` varchar(10) NOT NULL,
  `ref` varchar(255) NOT NULL,
  `disclosure_time` datetime(6) DEFAULT NULL,
  `created_time` datetime(6) DEFAULT NULL,
  `file` varchar(100) NOT NULL,
  `filename` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=207 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `poc`
--

LOCK TABLES `poc` WRITE;
/*!40000 ALTER TABLE `poc` DISABLE KEYS */;
INSERT INTO `poc` VALUES (182,'POC-00001','74cms plus/ajax_common.php sql 注入漏洞','74cms','','74cms plus/ajax_common.php 对编码的处理不恰当，在处理UTF8转成GBK后还对其进行了addslashes处理。转码后直接带入查询 而且直接输出','saline','注入','3','http://www.wooyun.org/bugs/wooyun-2014-063225','2014-09-02 16:00:00.000000','2015-03-29 16:00:00.000000','/opt/TScan/frame/poc/4849e426-a1d0-4ecb-bdfc-561e5927ba08-JeI4z9Sz.py','4849e426-a1d0-4ecb-bdfc-561e5927ba08-JeI4z9Sz.py'),(183,'POC-00002','bash 远程代码执行漏洞','bash','3.0-4.3','bash 3.0-4.3 存在一个漏洞，该漏洞可以通过构造环境变量的值来执行任意的脚本代码','wooyun','远程命令/代码执行','3','https://www.invisiblethreat.ca/2014/09/cve-2014-6271/','2014-09-16 16:00:00.000000','2014-09-16 16:00:00.000000','/opt/TScan/frame/poc/b60a7894-a091-470e-a01c-6e43448f5db8-mPLFJ0UE.py','b60a7894-a091-470e-a01c-6e43448f5db8-mPLFJ0UE.py'),(184,'POC-00003','Bonfire 0.7 /install.php 信息泄露漏洞 POC','Bonfire','0.7','由于install.php安装文件对已安装的程序进行检测后没有做好后续处理，导致执行/install/do_install的时候引发重安装而暴露管理员信息。','sockls','信息泄漏','1','http://www.mehmetince.net/ci-bonefire-reinstall-admin-account-vulnerability-analysis-exploit/','2014-07-31 16:00:00.000000','2014-07-31 16:00:00.000000','/opt/TScan/frame/poc/f1089166-b6e3-48ab-aa1b-a6de5a8d209b-ZsvANolm.py','f1089166-b6e3-48ab-aa1b-a6de5a8d209b-ZsvANolm.py'),(185,'POC-00004','数字校园平台V2.0 Department.aspx 注入漏洞','数字校园平台','2.0','数字校园平台V2.0 Department.aspx页面，CheckCourse方法中的 FullName 参数存在注入, 将导致敏感数据泄漏','sockls','注入','3','https://butian.360.cn','2017-08-20 16:00:00.000000','2017-08-20 16:00:00.000000','/opt/TScan/frame/poc/27a1fcf6-b437-4274-b96a-7a1ff00bd532-i4NzDLtW.py','27a1fcf6-b437-4274-b96a-7a1ff00bd532-i4NzDLtW.py'),(186,'POC-00005','数字校园平台V2.0 Common.aspx 注入漏洞','数字校园平台','2.0','数字校园平台V2.0 Common.aspx页面，params 参数存在注入, 将导致敏感数据泄漏','sockls','注入','3','https://butian.360.cn','2017-08-20 16:00:00.000000','2017-08-20 16:00:00.000000','/opt/TScan/frame/poc/e38dc749-cf4c-41dc-8204-f4804a7aea1c-GR7Ny2BV.py','e38dc749-cf4c-41dc-8204-f4804a7aea1c-GR7Ny2BV.py'),(187,'POC-00006','Discuz7.2 /faq.php sql注入漏洞 POC\'','Discuz','7.1,7.2','Discuz 7.1 or 7.2 has sql injection in faq.php.','sockls','注入','3','http://www.wooyun.org/bugs/wooyun-2010-066095','2014-09-16 16:00:00.000000','2014-09-16 16:00:00.000000','/opt/TScan/frame/poc/49dcda2d-6ae3-45a8-8ce0-5d1b2e92545c-FWih1ly0.py','49dcda2d-6ae3-45a8-8ce0-5d1b2e92545c-FWih1ly0.py'),(188,'POC-00007','eyou4 list_userinfo.php sql 注入漏洞','eyou','4','eyou4 邮件系统中 /php/bill/list_userinfo.php 中的 cp 参数存在注入, 将导致敏感数据泄漏','wooyun','注入','3','http://www.wooyun.org/bugs/wooyun-2014-058014','2014-07-22 16:00:00.000000','2014-09-22 16:00:00.000000','/opt/TScan/frame/poc/e8f346b4-fee3-471e-ad1d-5dedbb504f05-k2mIQORf.py','e8f346b4-fee3-471e-ad1d-5dedbb504f05-k2mIQORf.py'),(189,'POC-00008','FineCMS 1.x /extensions/function.php 代码执行漏洞','FineCMS','1.x','在/extensions/function.php中$data在一定条件下会带入eval函数，构造代码可造成代码执行。','sockls','注入','3','http://wooyun.org/bugs/wooyun-2014-061643','2014-09-16 16:00:00.000000','2014-09-16 16:00:00.000000','/opt/TScan/frame/poc/7e95f659-7c6f-43ac-b8b2-e9187ee4bf86-mMdLupzZ.py','7e95f659-7c6f-43ac-b8b2-e9187ee4bf86-mMdLupzZ.py'),(190,'POC-00009','j-easycms 任意文件下载','j-easycms','all','j-easycms downloadfile filename参数存在任意文件下载漏洞','sockls','任意文件操作','3','http://butian.360.cn','2017-08-13 16:00:00.000000','2017-08-13 16:00:00.000000','/opt/TScan/frame/poc/ae48f616-3b68-4709-b257-406fa55a9856-rN5vr4Yv.py','ae48f616-3b68-4709-b257-406fa55a9856-rN5vr4Yv.py'),(191,'POC-00010','mongodb 未授权访问','mongodb','all','mongodb 未授权访问, 可能导致敏感数据泄漏','wooyun','错误配置','2','http://drops.wooyun.org/运维安全/2470','2009-12-31 16:00:00.000000','2014-12-24 16:00:00.000000','/opt/TScan/frame/poc/da84f617-f3b7-4c7e-9f58-75fc7b191b23-QBjOsaAl.py','da84f617-f3b7-4c7e-9f58-75fc7b191b23-QBjOsaAl.py'),(192,'POC-00011','phpcms V9 /swfupload.swf XSS','phpcmsv9','','phpcms V9 /swfupload.swf XSS','侦探911','xss跨站脚本攻击','1','http://www.wooyun.org/bugs/wooyun-2014-069833','2017-11-21 08:55:25.257648','2017-11-21 08:55:25.257660','/opt/TScan/frame/poc/7ff84c8c-9573-4ddb-85a0-c8d7cca20e9b-DLAKZVDS.py','7ff84c8c-9573-4ddb-85a0-c8d7cca20e9b-DLAKZVDS.py'),(193,'POC-00012','Joomla! 1.5-3.4 远程代码执行漏洞','Joomla','1.5-3.4','Joomla! 1.5-3.4 代码执行漏洞','Zer0_0ne','远程命令/代码执行','3','https://blog.sucuri.net/2015/12/remote-command-execution-vulnerability-in-joomla.html','2015-12-15 16:00:00.000000','2015-12-15 16:00:00.000000','/opt/TScan/frame/poc/bb936693-ae9f-46e4-9dd9-1582db1586c6-R9ngaM3u.py','bb936693-ae9f-46e4-9dd9-1582db1586c6-R9ngaM3u.py'),(194,'POC-00013','phpmywind 4.6.6 /order.php SQL注入漏洞','phpmywind','4.6.6','PHPMyWind /order.php 中第372行\n                $r = $dosql->GetOne(\"SELECT `$colname` FROM `$tbname2` WHERE `id`=\".$_GET[\'id\']);\n                未对$_GET[\'id\']做任何过滤和检查，可以构造语句绕过后续检查进行报错注入。','tmp','注入','3','http://wooyun.org/bugs/wooyun-2010-051256/','2014-09-23 16:00:00.000000','2014-09-23 16:00:00.000000','/opt/TScan/frame/poc/0626ef6f-74a4-45aa-acd0-f86947faa6c3-IVJLYAXZ.py','0626ef6f-74a4-45aa-acd0-f86947faa6c3-IVJLYAXZ.py'),(195,'POC-00014','phpok 4.0.556 /api.php SQL注入漏洞','phpok','4.0.556','phpok 4.0.556 /api.php SQL注入漏洞','tmp','注入','3','http://www.wooyun.org/bugs/wooyun-2014-064360','2014-09-16 16:00:00.000000','2014-09-16 16:00:00.000000','/opt/TScan/frame/poc/d48fd986-191e-49ef-a3dd-3c9fd05052f9-DA9mZe4r.py','d48fd986-191e-49ef-a3dd-3c9fd05052f9-DA9mZe4r.py'),(196,'POC-00015','最土团购 /api/call.php SQL注入漏洞','最土团购','*','最土团购 /api/call.php SQL注入漏洞','Bug','注入','3','http://www.moonsec.com/post-11.html','2014-10-02 16:00:00.000000','2014-10-02 16:00:00.000000','/opt/TScan/frame/poc/1bc01768-940d-4c64-834a-5e4bf8733436-V6B6Mj9G.py','1bc01768-940d-4c64-834a-5e4bf8733436-V6B6Mj9G.py'),(197,'POC-00016','MacCMS v8 /inc_ajax.php SQL注入漏洞','MacCMS','v8','MacCMS V8版本中/inc/ajax.php文件tab参数未经过过滤带入SQL语句，导致SQL注入漏洞发生。','foundu','注入','3','http://wooyun.org/bugs/wooyun-2014-063677','2014-09-19 16:00:00.000000','2014-09-19 16:00:00.000000','/opt/TScan/frame/poc/4fc6a510-88c0-4851-a05b-4ef122c874dc-LLOtQaVN.py','4fc6a510-88c0-4851-a05b-4ef122c874dc-LLOtQaVN.py'),(198,'POC-00017','dedecms 5.7 /download.php 注入GETSHELL漏洞','dedecms','5.7','ExecuteNoneQuery2执行Sql但是没有进行防注入导致download.php有sql注入，进一步导致全局变量$GLOBALS可以被任意修改','foundu','远程命令/代码执行','3','http://yxmhero1989.blog.163.com/blog/static/1121579562013581535738/','2014-09-21 16:00:00.000000','2014-09-21 16:00:00.000000','/opt/TScan/frame/poc/f22c87b2-55a2-4464-9d1b-15f85c459d4e-wKyeI8JT.py','f22c87b2-55a2-4464-9d1b-15f85c459d4e-wKyeI8JT.py'),(199,'POC-00018','StartBBS /swfupload.swf 跨站脚本漏洞','StartBBS','1.1.15.*','StartBBS 1.1.15.* /plugins/kindeditor/plugins/multiimage/images/swfupload.swf Flash XSS','hang333','xss跨站脚本攻击','2','http://www.wooyun.org/bugs/wooyun-2014-049457/trace/bbf81ebe07bcc6021c3438868ae51051','2014-09-21 16:00:00.000000','2014-09-21 16:00:00.000000','/opt/TScan/frame/poc/bf50dca9-952a-4f5c-91d4-46e149914d57-EIVEZFTP.py','bf50dca9-952a-4f5c-91d4-46e149914d57-EIVEZFTP.py'),(200,'POC-00019','WordPress ShortCode Plugin 1.1 - Local File Inclusion Vulnerability','WordPress','1.1','WordPress shortcode 插件1.1版本存在任意文件下载漏洞','xidianlz','xss跨站脚本攻击','2','http://sebug.net/vuldb/ssvid-87214','2014-09-21 16:00:00.000000','2014-09-21 16:00:00.000000','/opt/TScan/frame/poc/5af9d12a-6c4d-47dd-919d-3d22a0830d0a-J23a1h1d.py','5af9d12a-6c4d-47dd-919d-3d22a0830d0a-J23a1h1d.py'),(201,'POC-00020','eYou v5 /em/controller/action/help.class.php SQL Injection','eYou','v5','eYou v5 has sql injection in /.','root','注入','3','http://wooyun.org/bugs/wooyun-2014-058014','2014-09-22 16:00:00.000000','2014-09-22 16:00:00.000000','/opt/TScan/frame/poc/3d7f5684-6d9c-409f-8ce5-43225f9cd54e-0Ad88rpP.py','3d7f5684-6d9c-409f-8ce5-43225f9cd54e-0Ad88rpP.py'),(202,'POC-00021','WordPress Acento Theme Arbitrary File Download','WordPress','','wp主题插件acento theme 中view-pad.php 文件,可读取任意文件','flsf','任意文件操作','3','http://www.exploit-db.com/exploits/34578/','2014-09-22 16:00:00.000000','2014-09-22 16:00:00.000000','/opt/TScan/frame/poc/01ab7cf8-6b99-466e-b559-fdfe4fbe1fed-bCpeZh6J.py','01ab7cf8-6b99-466e-b559-fdfe4fbe1fed-bCpeZh6J.py'),(203,'POC-00022','数字校园平台V2.0 Common.aspx 注入漏洞','数字校园平台','2.0','数字校园平台V2.0 Common.aspx页面，params 参数存在注入, 将导致敏感数据泄漏','sockls','注入','3','https://butian.360.cn','2017-08-20 16:00:00.000000','2017-08-20 16:00:00.000000','/opt/TScan/frame/poc/f3e0e191-da26-4cc6-8346-62e8896d80c9-6a4Q7JMC.py','f3e0e191-da26-4cc6-8346-62e8896d80c9-6a4Q7JMC.py'),(204,'POC-00023','数字校园平台V2.0 Department.aspx 注入漏洞','数字校园平台','2.0','数字校园平台V2.0 Department.aspx页面，CheckCourse方法中的 FullName 参数存在注入, 将导致敏感数据泄漏','sockls','注入','3','https://butian.360.cn','2017-08-20 16:00:00.000000','2017-08-20 16:00:00.000000','/opt/TScan/frame/poc/c39573c8-378d-4b68-af51-456edc6f9a9d-x6flLlqo.py','c39573c8-378d-4b68-af51-456edc6f9a9d-x6flLlqo.py'),(205,'POC-00024','源天软件OA办公系统 sql 注入MSSQL版漏洞（无需登录）','源天','','OA办公系统 /ServiceAction/com.velcro.base.DataAction 中的 sql 参数存在注入, 将导致敏感数据泄漏','Coody','注入','3','暂无','2015-07-21 16:00:00.000000','2015-07-22 16:00:00.000000','/opt/TScan/frame/poc/611cee3d-c0ec-425e-9a51-f321684c65a4-iy6vffEd.py','611cee3d-c0ec-425e-9a51-f321684c65a4-iy6vffEd.py'),(206,'POC-00025','安达通网关3g/g3/log命中执行漏洞','IAM网关控制台','x.6.660','安达通网关系统存在默认口令，用户名root 密码changeit。\n                可通过该账户登录系统,在\'3g/g3/log\'页面存在命令执行漏洞，\n                可直接执行系统命令,来获取系统权限。','sockls','远程命令/代码执行','3','http://vul.hu0g4.com/index.php/2017/11/21/5.html','2017-08-21 16:00:00.000000','2017-08-21 16:00:00.000000','/opt/TScan/frame/poc/132e6aee-24e5-430b-8991-ce5feb495f27-AAZwOMIS.py','132e6aee-24e5-430b-8991-ce5feb495f27-AAZwOMIS.py');
/*!40000 ALTER TABLE `poc` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `project_poc`
--

DROP TABLE IF EXISTS `project_poc`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `project_poc` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `poc_id` int(11) NOT NULL,
  `project_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `project_poc_poc_id_77ffa960_fk_poc_id` (`poc_id`),
  KEY `project_poc_project_id_ca719ee2_fk_projects_id` (`project_id`),
  CONSTRAINT `project_poc_poc_id_77ffa960_fk_poc_id` FOREIGN KEY (`poc_id`) REFERENCES `poc` (`id`),
  CONSTRAINT `project_poc_project_id_ca719ee2_fk_projects_id` FOREIGN KEY (`project_id`) REFERENCES `projects` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=56 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `project_poc`
--

LOCK TABLES `project_poc` WRITE;
/*!40000 ALTER TABLE `project_poc` DISABLE KEYS */;
INSERT INTO `project_poc` VALUES (53,206,131),(54,206,133),(55,206,135);
/*!40000 ALTER TABLE `project_poc` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `projects`
--

DROP TABLE IF EXISTS `projects`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `projects` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `url` varchar(255) NOT NULL,
  `status` varchar(10) NOT NULL,
  `created_time` datetime(6) NOT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `projects_user_id_155ff78a_fk_user_id` (`user_id`),
  CONSTRAINT `projects_user_id_155ff78a_fk_user_id` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=136 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `projects`
--

LOCK TABLES `projects` WRITE;
/*!40000 ALTER TABLE `projects` DISABLE KEYS */;
INSERT INTO `projects` VALUES (131,'http://221.224.120.187:8080','finish','2017-11-21 08:56:13.013390',1),(132,'http://vul.hu0g4.top/index.php/2017/11/21/5.html','finish','2017-11-24 03:11:45.425250',1),(133,'http://221.224.120.187:8080','finish','2017-11-24 03:12:25.124349',1),(134,'http://www.cert.org.cn','finish','2017-11-24 03:30:38.098650',1),(135,'http://221.224.120.187:8080','finish','2018-03-09 08:47:47.353937',1);
/*!40000 ALTER TABLE `projects` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user`
--

DROP TABLE IF EXISTS `user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `password` varchar(128) NOT NULL,
  `last_login` datetime(6) DEFAULT NULL,
  `is_superuser` tinyint(1) NOT NULL,
  `username` varchar(150) NOT NULL,
  `first_name` varchar(30) NOT NULL,
  `last_name` varchar(30) NOT NULL,
  `email` varchar(254) NOT NULL,
  `is_staff` tinyint(1) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `date_joined` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user`
--

LOCK TABLES `user` WRITE;
/*!40000 ALTER TABLE `user` DISABLE KEYS */;
INSERT INTO `user` VALUES (1,'pbkdf2_sha256$36000$SNL8zFOuGn8P$PyqC5Ha7CVV0BMimVv9MQ3oFn0Dv1pLB2dsfoB/NlCc=','2018-03-17 13:01:25.530369',0,'sockls','','','i@qvq.im',0,1,'2017-10-25 09:03:12.787951');
/*!40000 ALTER TABLE `user` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user_groups`
--

DROP TABLE IF EXISTS `user_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user_groups` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `group_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_groups_user_id_group_id_40beef00_uniq` (`user_id`,`group_id`),
  KEY `user_groups_group_id_b76f8aba_fk_auth_group_id` (`group_id`),
  CONSTRAINT `user_groups_group_id_b76f8aba_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`),
  CONSTRAINT `user_groups_user_id_abaea130_fk_user_id` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user_groups`
--

LOCK TABLES `user_groups` WRITE;
/*!40000 ALTER TABLE `user_groups` DISABLE KEYS */;
/*!40000 ALTER TABLE `user_groups` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user_user_permissions`
--

DROP TABLE IF EXISTS `user_user_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user_user_permissions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `permission_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_user_permissions_user_id_permission_id_7dc6e2e0_uniq` (`user_id`,`permission_id`),
  KEY `user_user_permission_permission_id_9deb68a3_fk_auth_perm` (`permission_id`),
  CONSTRAINT `user_user_permission_permission_id_9deb68a3_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  CONSTRAINT `user_user_permissions_user_id_ed4a47ea_fk_user_id` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user_user_permissions`
--

LOCK TABLES `user_user_permissions` WRITE;
/*!40000 ALTER TABLE `user_user_permissions` DISABLE KEYS */;
/*!40000 ALTER TABLE `user_user_permissions` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2018-03-21 10:26:46
