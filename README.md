# Sniffer-R-seau-avec-Detection-Anormale.

## Introduction

Ce projet implémente un **sniffer réseau avancé** en Python, capable de capturer du trafic réseau en temps réel, d'analyser certaines requêtes (DNS, HTTP), et de détecter des comportements anormaux basés sur un critère personnalisé. Il est conçu dans le cadre d'une évaluation de pentesting et s'inspire des concepts étudiés dans **Black Hat Python: Python For Pentesters**.

L'objectif principal est de démontrer la capacité à concevoir un outil capable de surveiller le trafic réseau et de repérer des activités suspectes selon des critères définis.

## Fonctionnalités

L'outil présente les fonctionnalités suivantes :

- **Capture du trafic réseau en temps réel** : Il permet de capturer le trafic d'une interface réseau (par exemple `eth0` ou `wlan0`).
- **Filtrage des requêtes** : Le sniffer est configuré pour capturer les requêtes HTTP, DNS et FTP.
- **Extraction d'informations utiles** : Le sniffer extrait les adresses IP sources et destinations, ainsi que les domaines/URLs accédés.
- **Détection d'activités suspectes** : Basée sur un critère personnalisé, il marque comme suspect un domaine ayant un nombre anormal de requêtes DNS.
- **Enregistrement des logs** : Toutes les requêtes et anomalies détectées sont enregistrées dans un fichier `traffic_log.txt` au format structuré.

## Installation

### Prérequis

- Python 3.x
- Scapy : une bibliothèque Python pour la manipulation de paquets réseau.

### Étapes d'installation

1. Clonez ce dépôt sur votre machine :
   ```bash
   git clone https://github.com/OwlHacker-source/Sniffer-R-seau-avec-Detection-Anormale
   ```
