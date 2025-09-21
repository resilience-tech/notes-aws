# Storage Part 1

## Overview

This document covers the fundamentals of AWS storage services.

## Topics

- Introduction to AWS Storage
- Amazon S3 basics
- Storage classes
- Basic operations

## Notes

# Storage Part 1

## Overview

This document covers the fundamentals of AWS storage services.

## Topics

- Introduction to AWS Storage
- Amazon S3 basics
- Storage classes
- Basic operations

## Notes

Add your notes here...

# AWS Storage – Part 1 (Comprehensive Overview)

## 1. Introduction
- AWS provides multiple storage options to meet diverse workload needs — from databases to backups to machine learning.
- Categories: Object, Block, File, Archival, and Hybrid storage.
- Evaluation criteria: Durability (S3: 99.999999999%), Availability (multi-AZ, regional options), Performance (IOPS, throughput), Scalability, Security (encryption, IAM policies), Cost models (pay-as-you-go, tiering).

## 2. Object Storage
### Amazon S3 (Simple Storage Service)
- Stores data as objects (file + metadata + unique ID).
- Virtually unlimited scalability with simple REST API access.
- **Features**: Versioning, lifecycle management, replication, encryption, and event-driven workflows.
- **Storage Classes**: 
  - S3 Standard
  - Intelligent-Tiering
  - Standard-IA / One Zone-IA
  - Glacier tiers (Instant, Flexible, Deep Archive)
- **Use cases**: Data lakes, analytics, ML datasets, backup & restore, static website hosting.

## 3. Block Storage
### Amazon EBS (Elastic Block Store)
- Block-level storage that attaches to EC2 instances like a disk.
- Persistent – survives instance stop/start.
- Snapshots integrated with S3 for backups.
- **Volume types**: gp3, io2/io2 Block Express, st1, sc1.
- **Use cases**: Databases, ERP, transactional workloads.

### Instance Store
- Physically attached NVMe/SATA storage with low latency.
- Ephemeral – data lost when instance stops or fails.
- **Use cases**: Caching, temporary scratch data, HPC workloads.

## 4. File Storage
### Amazon EFS (Elastic File System)
- Managed, scalable NFS file system.
- Supports thousands of clients and multiple AZs.
- **Use cases**: CMS, home directories, big data.

### Amazon FSx (Managed File Systems)
- FSx for Windows File Server → SMB protocol, AD integration.
- FSx for Lustre → HPC, big data, ML workloads.
- FSx for NetApp ONTAP → snapshots, deduplication, enterprise features.
- FSx for OpenZFS → Linux workloads.
- **Use cases**: enterprise storage, HPC, ML.

## 5. Archival Storage (Brief Overview)
- **Amazon S3 Glacier & Deep Archive**: ultra-low-cost, retrieval times vary.
- **Use cases**: Compliance, medical records, digital preservation.

## 6. Hybrid & Edge Storage (Brief Overview)
- **AWS Storage Gateway**: Hybrid storage (file, volume, tape).
- **AWS Snow Family**: Migration devices (Snowcone, Snowball, Snowmobile).
- **AWS DataSync**: Online large-scale data transfer.

## 7. Key Takeaways
- **S3 → Object storage** (scalable, durable).
- **EBS/Instance Store → Block storage** (fast, EC2-focused).
- **EFS/FSx → File storage** (shared, enterprise, HPC).
- **Glacier → Archival storage** (long-term, low cost).
- **Gateway/Snow/DataSync → Hybrid and migration**.

