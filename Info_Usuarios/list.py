import boto3
import pandas as pd
from datetime import datetime
from botocore.exceptions import ClientError

class GlobalIAMScanner:
    def __init__(self):
        # Obtiene todos los perfiles locales configurados
        self.session_profiles = boto3.Session().available_profiles
        self.all_data = []

    def get_user_data(self, profile_name):
        try:
            # Iniciamos sesión con el perfil específico
            session = boto3.Session(profile_name=profile_name)
            iam = session.client('iam')
            sts = session.client('sts')
            
            # Intentamos obtener el ID de la cuenta para el reporte
            account_id = sts.get_caller_identity()["Account"]
            print(f"[*] Procesando: {profile_name or 'Default'} (ID: {account_id})")

            paginator = iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    username = user['UserName']
                    create_date = user['CreateDate'].strftime('%m/%d/%Y')
                    
                    # 1. Acceso a Consola y MFA
                    last_login = user.get('PasswordLastUsed')
                    last_login_str = last_login.strftime('%m/%d/%Y') if last_login else "None"
                    console_access = "Yes" if last_login else "No"
                    
                    mfa_devices = iam.list_mfa_devices(UserName=username).get('MFADevices', [])
                    mfa_status = "Yes" if mfa_devices else "No"

                    # 2. Listar Access Keys y su estado
                    keys_metadata = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
                    
                    if not keys_metadata:
                        # Usuario sin llaves (solo consola o servicio)
                        self.all_data.append(self._build_row(
                            profile_name, account_id, username, create_date, 
                            last_login_str, console_access, mfa_status
                        ))
                    else:
                        for key in keys_metadata:
                            kid = key['AccessKeyId']
                            k_status = key['Status']  # <--- 'Active' o 'Inactive'
                            
                            # Detalle de último uso
                            usage_info = iam.get_access_key_last_used(AccessKeyId=kid)
                            usage = usage_info.get('AccessKeyLastUsed', {})
                            
                            last_used_date = usage.get('LastUsedDate')
                            last_used_str = last_used_date.strftime('%m/%d/%Y') if last_used_date else "None"
                            
                            self.all_data.append(self._build_row(
                                profile_name, account_id, username, create_date, 
                                last_login_str, console_access, mfa_status,
                                kid, k_status, last_used_str, 
                                usage.get('ServiceName', 'None'),
                                usage.get('Region', 'None')
                            ))

        except Exception as e:
            print(f"[!] Error en perfil {profile_name}: {e}")

    def _build_row(self, profile, acc_id, user, created, login, console, mfa, 
                   key="None", status="None", used="None", service="None", region="None"):
        return {
            "CUENTA": profile or "Default",
            "ID Cuenta": acc_id,
            "Usuarios": user,
            "CreateDate": created,
            "LastConsoleLogin": login,
            "ConsoleAccess": console,
            "AccessKeyId": key,
            "KeyStatus": status,      # <--- Nueva Columna
            "LastUsedDate": used,
            "ServiceName": service,
            "Region": region,
            "MFA": mfa
        }

    def run(self):
        # Si no hay perfiles, usamos el default
        profiles_to_scan = self.session_profiles if self.session_profiles else [None]
        
        for profile in profiles_to_scan:
            self.get_user_data(profile)

        if self.all_data:
            df = pd.DataFrame(self.all_data)
            # Ordenar para que las llaves activas salgan primero
            df = df.sort_values(by=['CUENTA', 'KeyStatus'], ascending=[True, True])
            
            filename = f"reporte_iam_detallado_{datetime.now().strftime('%Y%m%d')}.csv"
            df.to_csv(filename, index=False, encoding='utf-8-sig')
            print(f"\n[OK] Reporte generado: {filename} con {len(df)} registros.")
        else:
            print("[?] No se encontraron datos.")

if __name__ == "__main__":
    scanner = GlobalIAMScanner()
    scanner.run()
