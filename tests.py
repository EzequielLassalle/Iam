"""
tests.py
========
Suite de tests del proyecto. Runner propio, sin dependencias.

Cubre el motor de evaluacion, la resolucion de policies, los escenarios y la auditoria.

Los tests del bloque "regresiones" son los mas importantes: cada uno corresponde a un bug
real que el motor tuvo y que ya fue corregido. Estan escritos para que, si alguien vuelve
a romperlo, se entere. Los tres eran fallas de las que otorgan permisos de mas, que es la
unica clase de error que un motor de autorizacion no puede permitirse.

    python tests.py
    python main.py test
"""

from __future__ import annotations

import copy
import sys
import traceback

import admin_cuenta as admin
import recursos as recursos_mod
import simulador
from auditoria import (cargar_eventos, detectar_anomalias, es_admin,
                       revisar_credenciales)
from contexto import (cargar_cuenta, cargar_recursos, peticion,
                      policies_de_recurso, policies_de_usuario, tags_de_recurso)
from escenarios import ESCENARIOS
from motor_iam import accion_coincide, evaluar, recurso_coincide

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

CUENTA = cargar_cuenta()
EVENTOS = cargar_eventos()
ACCOUNT = CUENTA["AccountId"]
ACCOUNT_AUDIT = "222222222222"
POL = CUENTA["ManagedPolicies"]
SCP = CUENTA["Organization"]["SCPs"]["GuardrailBase"]

OBJETO_NOMINA = "arn:aws:s3:::banco-backups/nomina.xlsx"


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

def hay_hallazgo(hallazgos, categoria, sujeto):
    """True si la auditoria reporto esa categoria sobre ese sujeto."""
    return any(h.categoria == categoria and h.sujeto == sujeto for h in hallazgos)


def decision(peticion, policies):
    """Corre el motor y devuelve solo la decision."""
    return evaluar(peticion, policies).decision


# ---------------------------------------------------------------------------
# El motor: el orden de decision
# ---------------------------------------------------------------------------

def test_allow_explicito():
    """Una accion que la policy permite y un recurso que matchea: pasa."""
    pol = {"identity": [("S3ReadOnlyBackups", POL["S3ReadOnlyBackups"])]}
    d = decision({"action": "s3:GetObject", "resource": OBJETO_NOMINA}, pol)
    assert d == "Allow", f"esperaba Allow y dio {d}"


def test_deny_implicito():
    """Una accion que ninguna policy menciona queda denegada: IAM arranca todo cerrado."""
    pol = {"identity": [("S3ReadOnlyBackups", POL["S3ReadOnlyBackups"])]}
    d = decision({"action": "s3:DeleteObject", "resource": OBJETO_NOMINA}, pol)
    assert d == "Deny", f"esperaba Deny (implicito) y dio {d}"


def test_recurso_que_no_matchea():
    """La policy permite la accion, pero sobre otro bucket."""
    pol = {"identity": [("S3ReadOnlyBackups", POL["S3ReadOnlyBackups"])]}
    d = decision({"action": "s3:GetObject", "resource": "arn:aws:s3:::otro-bucket/x"}, pol)
    assert d == "Deny", f"esperaba Deny y dio {d}"


def test_deny_explicito_le_gana_al_allow_total():
    """El Deny de la SCP prevalece sobre un Allow '*' en la identity policy."""
    pol = {"identity": [("AdministratorAccess", POL["AdministratorAccess"])],
           "scp": [("GuardrailBase", SCP)]}
    d = decision({"principal": f"arn:aws:iam::{ACCOUNT}:user/jadmin",
                  "action": "cloudtrail:StopLogging", "resource": "*"}, pol)
    assert d == "Deny", f"el Deny de la SCP tiene que ganarle al Allow '*', pero dio {d}"


def test_scp_no_otorga_permisos():
    """La SCP es un techo, no una fuente de permisos: sin Allow en identity, Deny."""
    pol = {"identity": [("S3ReadOnlyBackups", POL["S3ReadOnlyBackups"])],
           "scp": [("GuardrailBase", SCP)]}
    d = decision({"principal": f"arn:aws:iam::{ACCOUNT}:user/cgomez",
                  "action": "ec2:TerminateInstances",
                  "resource": f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0abc"}, pol)
    assert d == "Deny", f"la SCP no deberia OTORGAR el permiso, pero dio {d}"


def test_boundary_recorta_pero_no_es_un_deny_generico():
    """Fuera de la interseccion identity/boundary: Deny. Dentro: Allow."""
    pol = {"identity": [("AdministratorAccess", POL["AdministratorAccess"])],
           "boundary": [("BoundaryS3ReadOnly", POL["BoundaryS3ReadOnly"])]}
    base = {"principal": f"arn:aws:iam::{ACCOUNT}:user/dev", "principal_account": ACCOUNT}

    fuera = decision({**base, "action": "iam:CreateUser", "resource": "*"}, pol)
    dentro = decision({**base, "action": "s3:PutObject",
                       "resource": "arn:aws:s3:::banco-backups/x.txt"}, pol)

    assert fuera == "Deny", f"iam:CreateUser esta fuera del boundary: esperaba Deny, dio {fuera}"
    assert dentro == "Allow", f"s3:PutObject esta dentro del boundary: esperaba Allow, dio {dentro}"


def test_capa_vacia_bloquea_todo_capa_ausente_no_bloquea_nada():
    """
    [] y None no son lo mismo en una capa-techo, y confundirlos invierte el resultado.

    [] = la capa existe y no permite nada -> bloquea todo.
    None (o ausente) = la capa no aplica  -> no bloquea nada.
    """
    identity = [("AdministratorAccess", POL["AdministratorAccess"])]
    pet = {"principal": f"arn:aws:iam::{ACCOUNT}:user/x", "principal_account": ACCOUNT,
           "action": "s3:GetObject", "resource": OBJETO_NOMINA}

    con_boundary_vacio = decision(pet, {"identity": identity, "boundary": []})
    sin_boundary = decision(pet, {"identity": identity})

    assert con_boundary_vacio == "Deny", "un boundary vacio no permite nada: tiene que bloquear"
    assert sin_boundary == "Allow", "sin boundary no hay techo que bloquear"


def test_cross_account_necesita_las_dos_puntas():
    """Cross-account: sin resource policy en la cuenta duena del recurso, Deny."""
    pet = {"principal": f"arn:aws:iam::{ACCOUNT_AUDIT}:user/auditor",
           "principal_account": ACCOUNT_AUDIT,
           "action": "s3:GetObject",
           "resource": OBJETO_NOMINA,
           "resource_account": ACCOUNT,
           "context": {}}
    identity = [("S3ReadOnlyBackups", POL["S3ReadOnlyBackups"])]

    sin = decision(pet, {"identity": identity})
    con = decision(pet, {"identity": identity,
                         "resource": policies_de_recurso(CUENTA, OBJETO_NOMINA)})

    assert sin == "Deny", f"sin bucket policy esperaba Deny y dio {sin}"
    assert con == "Allow", f"con bucket policy esperaba Allow y dio {con}"


# ---------------------------------------------------------------------------
# Regresiones: bugs reales que el motor tuvo. Que no vuelvan.
# ---------------------------------------------------------------------------

def test_regresion_deny_con_condicion_irresoluble_deniega():
    """
    Un Deny cuya condicion el motor no puede resolver tiene que APLICAR igual, y tiene que
    hacerlo TAMBIEN cuando la clave de condicion no viaja en la peticion.

    El bug, en dos etapas:
      1. La condicion irresoluble se trataba como "no se cumple", el Deny no aplicaba y la
         peticion pasaba. Fail-OPEN.
      2. El primer intento de arreglo solo cubrio el caso de la clave PRESENTE. Con la
         clave ausente, el chequeo de "clave ausente" corria antes que el del operador
         desconocido, devolvia False, y el Deny se evaporaba igual. El fail-open seguia
         ahi, y el test lo tapaba porque metia la clave en el contexto.

    Por eso este test prueba las dos variantes, y la de la clave ausente es la que importa:
    aws:TagKeys justamente NO viaja en una llamada que no etiqueta nada.
    """
    pol = {"identity": [
        ("AdministratorAccess", POL["AdministratorAccess"]),
        ("DenyRaro", {"Statement": [{
            "Effect": "Deny", "Action": "s3:*", "Resource": "*",
            # Operador de conjunto que el motor no implementa.
            "Condition": {"ForAllValues:StringEquals": {"aws:TagKeys": ["Proyecto"]}}}]}),
    ]}
    base = {"principal": f"arn:aws:iam::{ACCOUNT}:user/x",
            "action": "s3:GetObject", "resource": OBJETO_NOMINA}

    presente = decision({**base, "context": {"aws:TagKeys": "Proyecto"}}, pol)
    ausente = decision({**base, "context": {}}, pol)

    assert presente == "Deny", f"clave presente: esperaba Deny y dio {presente}"
    assert ausente == "Deny", (
        "clave AUSENTE: el Deny se evaporo y la peticion paso. Es fail-open: el operador "
        f"desconocido tiene que detectarse ANTES que la clave ausente. Dio {ausente}")


def test_regresion_allow_con_condicion_irresoluble_no_otorga():
    """La otra cara: ante la duda, un Allow no otorga. Tambien con la clave ausente."""
    pol = {"identity": [("AllowRaro", {"Statement": [{
        "Effect": "Allow", "Action": "s3:*", "Resource": "*",
        "Condition": {"ForAllValues:StringEquals": {"aws:TagKeys": ["Proyecto"]}}}]})]}
    base = {"principal": f"arn:aws:iam::{ACCOUNT}:user/x",
            "action": "s3:GetObject", "resource": OBJETO_NOMINA}

    for ctx, etiqueta in (({"aws:TagKeys": "Proyecto"}, "presente"), ({}, "ausente")):
        d = decision({**base, "context": ctx}, pol)
        assert d == "Deny", f"clave {etiqueta}: un Allow irresoluble no otorga, dio {d}"


def test_regresion_el_orden_de_los_statements_no_cambia_la_decision():
    """
    En IAM no hay precedencia entre statements: el resultado no puede depender del orden.

    El bug (colateral del fix de ':root'): _hay_match se quedaba con el PRIMER statement que
    matcheaba. Si la bucket policy tenia primero un ':root' (delegado) y despues uno que
    nombraba al usuario (directo), se quedaba con el delegado y denegaba. Dando vuelta el
    orden, permitia. Misma policy, distinto resultado.
    """
    pet = {"principal": f"arn:aws:iam::{ACCOUNT}:user/pepe",
           "principal_account": ACCOUNT,
           "action": "s3:GetObject", "resource": "arn:aws:s3:::b/k.txt", "context": {}}

    delegado = {"Sid": "Delegado", "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}
    directo = {"Sid": "Directo", "Effect": "Allow",
               "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:user/pepe"},
               "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}

    def con_orden(statements):
        return decision(pet, {"identity": [],
                              "resource": [("BucketPolicy", {"Statement": statements})]})

    a = con_orden([delegado, directo])
    b = con_orden([directo, delegado])

    assert a == b == "Allow", (
        "el statement directo otorga por si solo, este escrito antes o despues del "
        f"delegado. Dio {a} con un orden y {b} con el otro")


def test_regresion_comodines_son_los_de_iam_y_no_los_de_fnmatch():
    """
    IAM tiene exactamente dos comodines: '*' y '?'. Los corchetes son literales.

    El bug: se usaba fnmatch, que ademas interpreta [...] como clase de caracteres. Como
    las claves de S3 admiten corchetes, un patron 'bucket/[dev]-*' matcheaba 'bucket/d-x'
    -> un falso Allow sobre un objeto que la policy no nombraba.
    """
    assert not recurso_coincide("arn:aws:s3:::b/[dev]-*", "arn:aws:s3:::b/d-x"), \
        "los corchetes son literales en IAM: no deberia matchear"
    assert recurso_coincide("arn:aws:s3:::b/[dev]-*", "arn:aws:s3:::b/[dev]-x"), \
        "el corchete literal si tiene que matchear consigo mismo"

    # Los dos comodines que si existen siguen andando.
    assert recurso_coincide("arn:aws:s3:::b/*", "arn:aws:s3:::b/carpeta/k.txt")
    assert accion_coincide("s3:Get?bject", "s3:GetObject")


def test_regresion_root_en_un_principal_delega_pero_no_otorga():
    """
    Un Principal ':root' en una resource policy NO otorga por si solo: delega en la cuenta.

    El bug: el motor lo trataba como cualquier otro Allow de resource policy, asi que un
    usuario sin ninguna identity policy podia leer el bucket. En AWS eso es Deny: ':root'
    significa "que decida esa cuenta", y esa cuenta todavia tiene que permitirlo en la
    identity policy del principal.

    Si en cambio el Principal nombra al usuario directamente, ahi si otorga solo.
    """
    pet = {"principal": f"arn:aws:iam::{ACCOUNT}:user/pepe",
           "principal_account": ACCOUNT,
           "action": "s3:GetObject", "resource": "arn:aws:s3:::b/k.txt", "context": {}}

    delegado = [("BucketPolicy", {"Statement": [{
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
        "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]})]
    directo = [("BucketPolicy", {"Statement": [{
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:user/pepe"},
        "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]})]

    sin_identity = {"identity": []}
    con_identity = {"identity": [("S3", {"Statement": [{
        "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})]}

    d1 = decision(pet, {**sin_identity, "resource": delegado})
    d2 = decision(pet, {**con_identity, "resource": delegado})
    d3 = decision(pet, {**sin_identity, "resource": directo})

    assert d1 == "Deny", f"':root' delega y no otorga: sin identity policy es Deny, dio {d1}"
    assert d2 == "Allow", f"':root' + identity policy que lo permite: Allow, dio {d2}"
    assert d3 == "Allow", f"un Principal que nombra al usuario si otorga solo, dio {d3}"


# ---------------------------------------------------------------------------
# Condiciones
# ---------------------------------------------------------------------------

def test_bool_no_matchea_si_la_clave_esta_ausente():
    """
    Bool con la clave ausente no matchea, asi que el Deny condicional no aplica y la
    peticion pasa. Es la razon por la que se usa BoolIfExists para forzar MFA.
    """
    pol = {"identity": [("AdministratorAccess", POL["AdministratorAccess"]),
                        ("NegarSinMFA", POL["NegarSinMFA"])]}
    base = {"principal": f"arn:aws:iam::{ACCOUNT}:user/jadmin",
            "action": "s3:GetObject", "resource": OBJETO_NOMINA}

    sin_mfa = decision({**base, "context": {"aws:MultiFactorAuthPresent": "false"}}, pol)
    sin_clave = decision({**base, "context": {}}, pol)

    assert sin_mfa == "Deny", f"con MFA=false el Deny tiene que aplicar, pero dio {sin_mfa}"
    assert sin_clave == "Allow", (
        "con la clave ausente, Bool no matchea y el Deny no aplica: esperaba Allow (la fuga "
        f"que arregla BoolIfExists) y dio {sin_clave}")


def test_acciones_case_insensitive_recursos_case_sensitive():
    """Las acciones de IAM no distinguen mayusculas; los ARN de recursos si."""
    assert accion_coincide("s3:GetObject", "s3:getobject")
    assert accion_coincide("s3:*", "s3:DeleteObject")
    assert not accion_coincide("s3:Get*", "s3:PutObject")
    assert not recurso_coincide("arn:aws:s3:::MiBucket/*", "arn:aws:s3:::mibucket/x")


# ---------------------------------------------------------------------------
# Resolucion de policies
# ---------------------------------------------------------------------------

def test_usuario_hereda_las_policies_de_su_grupo():
    """
    La identity de un usuario es la UNION de sus policies directas y las de sus grupos.

    El test tiene que ejercitar herencia de verdad: cgomez no tiene ninguna policy directa,
    asi que todo lo que puede hacer lo hereda del grupo Creditos. Si la resolucion de grupos
    estuviera rota, cgomez se quedaria sin permisos y esto se caeria.

    (La version anterior de este test era vacua: todos los usuarios tenian duplicada en
    AttachedPolicies la misma policy que ya les daba su grupo, asi que pasaba igual aunque
    la herencia no funcionara.)
    """
    cgomez = policies_de_usuario(CUENTA, "cgomez")
    nombres = [n for n, _ in cgomez["identity"]]

    assert "S3ReadOnlyBackups" in nombres, \
        f"cgomez tiene que heredar S3ReadOnlyBackups del grupo Creditos: {nombres}"
    assert cgomez["_origen"]["S3ReadOnlyBackups"] == "grupo Creditos", \
        f"hay que poder rastrear la procedencia: dio {cgomez['_origen']}"

    # mlopez: una directa y una heredada. La union tiene que traer las dos.
    mlopez = policies_de_usuario(CUENTA, "mlopez")
    origen = mlopez["_origen"]
    assert origen.get("CreditosABAC") == "directa", "CreditosABAC esta pegada al usuario"
    assert origen.get("S3ReadOnlyBackups") == "grupo Creditos", "esta viene del grupo"


def test_operadores_negados_son_todos_operadores_implementados():
    """
    Los dos conjuntos tienen que ser coherentes, y en las dos direcciones.

    Si un operador figura como negado pero _comparar no lo implementa, con la clave presente
    revienta. Si esta implementado y falta en la lista de negados, con la clave ausente se
    comporta al reves de lo que corresponde. Los dos bugs existieron.
    """
    from motor_iam import _OPERADORES_CONOCIDOS, _OPERADORES_NEGADOS

    huerfanos = _OPERADORES_NEGADOS - _OPERADORES_CONOCIDOS
    assert not huerfanos, f"declarados como negados pero no implementados: {huerfanos}"

    for op in ("StringNotEqualsIgnoreCase", "DateNotEquals"):
        assert op in _OPERADORES_NEGADOS, f"{op} es un operador negado y falta en la lista"


def test_los_operadores_hacen_or_sobre_la_lista_de_valores():
    """
    Cuando la policy lista varios valores, alcanza con que matchee uno.

    El bug: Bool, Numeric* y Date* solo miraban el primer valor de la lista.
    """
    def cond(condicion, ctx):
        pol = {"identity": [("P", {"Statement": [{
            "Effect": "Allow", "Action": "s3:*", "Resource": "*",
            "Condition": condicion}]})]}
        return decision({"principal": f"arn:aws:iam::{ACCOUNT}:user/x",
                         "action": "s3:GetObject", "resource": OBJETO_NOMINA,
                         "context": ctx}, pol)

    d = cond({"NumericEquals": {"k": ["9", "5"]}}, {"k": "5"})
    assert d == "Allow", f"5 esta en la lista [9, 5]: esperaba Allow y dio {d}"

    d = cond({"StringEquals": {"k": ["a", "b"]}}, {"k": "b"})
    assert d == "Allow", f"b esta en la lista: esperaba Allow y dio {d}"


def test_una_identity_policy_sin_resource_no_otorga():
    """
    En una identity policy el Resource es obligatorio: sin el, la policy es invalida.

    El bug: el default era '*', asi que un statement sin Resource abria todo. En una
    RESOURCE policy, en cambio, el recurso esta implicito (es aquel al que esta pegada) y
    omitirlo es valido.
    """
    sin_resource = {"identity": [("Rota", {"Statement": [{
        "Effect": "Allow", "Action": "s3:*"}]})]}
    d = decision({"principal": f"arn:aws:iam::{ACCOUNT}:user/x",
                  "action": "s3:GetObject", "resource": OBJETO_NOMINA}, sin_resource)
    assert d == "Deny", f"una identity policy sin Resource no otorga nada, pero dio {d}"


def test_el_boundary_solo_aparece_si_el_usuario_lo_tiene():
    """La capa boundary solo debe existir si el usuario tiene uno asignado."""
    con = policies_de_usuario(CUENTA, "svc-reporting")
    sin = policies_de_usuario(CUENTA, "mlopez")
    assert "boundary" in con, "svc-reporting tiene un permission boundary"
    assert "boundary" not in sin, (
        "mlopez no tiene boundary, y esa capa NO debe aparecer: una capa vacia bloquearia "
        "todo, que es lo contrario de no tener capa")


def test_la_bucket_policy_se_resuelve_por_el_arn_del_objeto():
    """Un objeto hereda la resource policy de su bucket."""
    assert policies_de_recurso(CUENTA, OBJETO_NOMINA), \
        "el objeto tendria que heredar la bucket policy de banco-backups"
    assert not policies_de_recurso(CUENTA, "arn:aws:s3:::otro-bucket/x.txt"), \
        "otro-bucket no tiene ninguna resource policy"


# ---------------------------------------------------------------------------
# Los escenarios
# ---------------------------------------------------------------------------

def test_los_escenarios_dan_lo_esperado():
    """Cada escenario declara su resultado correcto: el motor tiene que coincidir en todos."""
    fallos = []
    for i, e in enumerate(ESCENARIOS, 1):
        obtenido = evaluar(e.peticion, e.policies).decision
        if obtenido != e.esperado:
            fallos.append(f"#{i} ({e.titulo}): esperaba {e.esperado} y dio {obtenido}")
    assert not fallos, "escenarios que no dieron lo esperado:\n    " + "\n    ".join(fallos)


# ---------------------------------------------------------------------------
# La auditoria
# ---------------------------------------------------------------------------

def test_identifica_a_los_administradores():
    """es_admin() tiene que ver AdministratorAccess, venga directo o heredado del grupo."""
    assert es_admin(CUENTA, "jadmin"), "jadmin esta en el grupo Administradores"
    assert not es_admin(CUENTA, "cgomez"), "cgomez solo tiene lectura de S3"


def test_encuentra_los_problemas_de_credenciales():
    """Los hallazgos sembrados en el dataset deben salir todos."""
    h = revisar_credenciales(CUENTA)

    assert hay_hallazgo(h, "mfa-ausente", "jadmin"), "jadmin es admin y no tiene MFA"
    assert hay_hallazgo(h, "privilegio-maximo", "jadmin"), "jadmin tiene AdministratorAccess"
    assert hay_hallazgo(h, "key-nunca-usada", "svc-reporting"), \
        "svc-reporting tiene una access key activa que nunca se uso"
    assert hay_hallazgo(h, "key-abandonada", "temp-consultor"), \
        "la key de temp-consultor no se usa hace 180 dias"
    assert hay_hallazgo(h, "usuario-inactivo", "temp-consultor"), \
        "temp-consultor no se loguea hace 180 dias"

    critico = [x for x in h if x.severidad == "CRITICO"]
    assert any(x.sujeto == "jadmin" for x in critico), \
        "un administrador sin MFA tiene que escalar a CRITICO"


def test_no_marca_a_los_usuarios_sanos():
    """
    Control de falsos positivos: cgomez tiene MFA, esta activa y sus permisos son acotados,
    asi que no debe generar hallazgos de severidad alta. Un reporte que marca a todo el
    mundo no sirve para nada.
    """
    graves = [x for x in revisar_credenciales(CUENTA)
              if x.sujeto == "cgomez" and x.severidad in ("CRITICO", "ALTO")]
    assert not graves, f"cgomez no deberia tener hallazgos graves, pero tiene: {graves}"


def test_detecta_la_actividad_sospechosa():
    """Las anomalias sembradas en el historial deben detectarse todas."""
    h = detectar_anomalias(CUENTA, EVENTOS)

    assert hay_hallazgo(h, "uso-de-root", "root"), "hubo un login de root"
    assert hay_hallazgo(h, "rafaga-denegados", "temp-consultor"), \
        "temp-consultor acumulo 6 AccessDenied seguidos"
    assert hay_hallazgo(h, "anti-forense", "jadmin"), \
        "jadmin intento apagar CloudTrail (StopLogging / DeleteTrail)"
    assert hay_hallazgo(h, "escalada-privilegios", "jadmin"), \
        "jadmin encadeno CreateUser + AttachUserPolicy + CreateAccessKey"
    assert hay_hallazgo(h, "ip-no-corporativa", "45.133.1.90"), \
        "la IP 45.133.1.90 esta fuera de las redes declaradas"


# ---------------------------------------------------------------------------
# El simulador: la misma decision que el catalogo, por la via generica
# ---------------------------------------------------------------------------

def test_simulador_reproduce_el_catalogo():
    """
    Los escenarios que parten de usuarios reales, evaluados por la via generica del
    simulador, dan lo mismo que el catalogo.

    Es la prueba de que 'evaluar' no es un camino paralelo con reglas propias: si el
    simulador y el catalogo divergieran, uno de los dos estaria mintiendo.
    """
    casos = [
        ("cgomez", "s3:DeleteObject", OBJETO_NOMINA, "Deny"),          # esc. 1
        ("jadmin", "cloudtrail:StopLogging", "*", "Deny"),             # esc. 2
        ("cgomez", "ec2:TerminateInstances",
         f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0abc", "Deny"),  # esc. 3
    ]
    for usuario, accion, recurso, esperado in casos:
        pet, capas = simulador.construir(CUENTA, usuario, accion, recurso)
        d = evaluar(pet, capas).decision
        assert d == esperado, f"{usuario} {accion}: esperaba {esperado} y dio {d}"


def test_simulador_adjunta_la_resource_policy_del_recurso():
    """La bucket policy se evalua aunque el llamante no la mencione: la trae el recurso."""
    _, capas = simulador.construir(CUENTA, "cgomez", "s3:GetObject", OBJETO_NOMINA)
    assert "resource" in capas, "no adjunto la resource policy del bucket"

    _, sin_rp = simulador.construir(CUENTA, "cgomez", "s3:GetObject",
                                    "arn:aws:s3:::otro-bucket/x")
    assert "resource" not in sin_rp, "adjunto una resource policy que no existe"


def test_simulador_puede_forzar_el_contexto():
    """El MFA de la peticion se puede pisar sin tocar la cuenta: es contexto, no estado."""
    pet, _ = simulador.construir(CUENTA, "cgomez", "s3:GetObject", OBJETO_NOMINA, mfa=False)
    assert pet["context"]["aws:MultiFactorAuthPresent"] == "false"


# ---------------------------------------------------------------------------
# admin_cuenta: las validaciones son lo que se testea
# ---------------------------------------------------------------------------

def copia():
    """Copia de la cuenta para mutar en memoria. Ningun test escribe en disco."""
    return copy.deepcopy(CUENTA)


def rechaza(fn, *args, **kwargs):
    """True si la mutacion fue rechazada por validacion."""
    try:
        fn(*args, **kwargs)
    except admin.ErrorAdmin:
        return True
    return False


def test_admin_rechaza_policy_inexistente():
    """Una policy fantasma en AttachedPolicies rompe la resolucion: hay que atajarla antes."""
    c = copia()
    assert rechaza(admin.attach_policy, c, "NoExiste", usuario="cgomez")
    assert rechaza(admin.crear_usuario, c, "nuevo", policies=["NoExiste"])
    assert rechaza(admin.set_boundary, c, "cgomez", "NoExiste")


def test_admin_rechaza_duplicados():
    c = copia()
    assert rechaza(admin.crear_usuario, c, "cgomez")
    assert rechaza(admin.crear_grupo, c, "Creditos")
    assert rechaza(admin.crear_policy, c, "S3ReadOnlyBackups", {"Statement": []})


def test_admin_rechaza_borrar_una_policy_en_uso():
    """Borrarla dejaria referencias colgadas en los usuarios y grupos que la tienen."""
    c = copia()
    assert rechaza(admin.borrar_policy, c, "S3ReadOnlyBackups")
    assert "S3ReadOnlyBackups" in c["ManagedPolicies"], "la borro igual"


def test_admin_rechaza_documento_invalido():
    c = copia()
    assert rechaza(admin.crear_policy, c, "X", {"Statement": [{"Effect": "Quizas"}]})
    assert rechaza(admin.crear_policy, c, "X", {"Statement": [{"Effect": "Allow"}]})
    assert rechaza(admin.crear_policy, c, "X", {"no": "tiene statement"})


def test_admin_rechaza_resource_policy_sin_principal():
    """Una resource policy sin Principal no dice a quien le habla: no es una resource policy."""
    c = copia()
    doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                          "Resource": "arn:aws:s3:::x/*"}]}
    assert rechaza(admin.set_resource_policy, c, "arn:aws:s3:::x", doc)


def test_admin_attach_a_grupo_lo_heredan_los_miembros():
    """El efecto de adjuntar a un grupo se ve en los permisos efectivos de sus miembros."""
    c = copia()
    admin.crear_policy(c, "EC2Full", {"Statement": [
        {"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}]})
    admin.attach_policy(c, "EC2Full", grupo="Creditos")

    nombres = [n for n, _ in policies_de_usuario(c, "cgomez")["identity"]]
    assert "EC2Full" in nombres, "cgomez no heredo la policy del grupo"

    d = decision({"action": "ec2:TerminateInstances", "resource": "*"},
                 policies_de_usuario(c, "cgomez"))
    assert d == "Allow", f"esperaba Allow tras heredar EC2Full y dio {d}"


def test_admin_boundary_recorta_lo_que_la_identity_otorga():
    """Poner un boundary no otorga nada: solo puede recortar. Es el escenario 4, mutando."""
    c = copia()
    admin.attach_policy(c, "AdministratorAccess", usuario="cgomez")

    pet = {"principal": f"arn:aws:iam::{ACCOUNT}:user/cgomez", "action": "iam:CreateUser",
           "resource": "*", "context": {}}
    assert decision(pet, policies_de_usuario(c, "cgomez")) == "Allow"

    admin.set_boundary(c, "cgomez", "BoundaryS3ReadOnly")
    d = decision(pet, policies_de_usuario(c, "cgomez"))
    assert d == "Deny", f"el boundary no recorto: dio {d}"


def test_admin_usuario_nuevo_arranca_sin_permisos():
    """Un usuario recien creado no puede nada: deny implicito, el punto de partida de IAM."""
    c = copia()
    admin.crear_usuario(c, "pasante")
    capas = policies_de_usuario(c, "pasante")
    assert capas["identity"] == [], "un usuario nuevo no deberia tener identity policies"

    d = decision({"action": "s3:GetObject", "resource": OBJETO_NOMINA}, capas)
    assert d == "Deny", f"un usuario sin policies dio {d}"


# ---------------------------------------------------------------------------
# Inventario de recursos: el aws:ResourceTag sale del recurso, no del contexto
# ---------------------------------------------------------------------------

INSTANCIA_CREDITOS = "arn:aws:ec2:us-east-1:111111111111:instance/i-0credito01"
INSTANCIA_SEGUROS = "arn:aws:ec2:us-east-1:111111111111:instance/i-0seguros01"


def test_tags_de_recurso_directo_y_heredado():
    """Un objeto hereda los tags de su bucket, igual que la resource policy."""
    assert tags_de_recurso("arn:aws:s3:::banco-backups").get("Proyecto") == "Creditos"
    assert tags_de_recurso(OBJETO_NOMINA).get("Proyecto") == "Creditos"  # hereda del bucket
    assert tags_de_recurso("arn:aws:s3:::no-existe") == {}


def test_el_resource_tag_se_puebla_desde_el_recurso():
    """Al armar la peticion, el aws:ResourceTag sale del inventario sin pasarlo por contexto."""
    pet = peticion(CUENTA, "mlopez", "ec2:StartInstances", INSTANCIA_CREDITOS)
    assert pet["context"].get("aws:ResourceTag/Proyecto") == "Creditos"


def test_ctx_pisa_el_tag_del_recurso():
    """--ctx (extra) gana sobre el tag real: forzar una hipotesis siempre manda."""
    pet = peticion(CUENTA, "mlopez", "ec2:StartInstances", INSTANCIA_CREDITOS,
                   **{"aws:ResourceTag/Proyecto": "Seguros"})
    assert pet["context"]["aws:ResourceTag/Proyecto"] == "Seguros"


def test_abac_sin_ctx_reparte_por_proyecto():
    """El ABAC decide con el tag real del recurso: mlopez alcanza Creditos y no Seguros."""
    capas = policies_de_usuario(CUENTA, "mlopez")
    permite = decision(peticion(CUENTA, "mlopez", "ec2:StartInstances", INSTANCIA_CREDITOS), capas)
    niega = decision(peticion(CUENTA, "mlopez", "ec2:StartInstances", INSTANCIA_SEGUROS), capas)
    assert permite == "Allow", f"la instancia de Creditos deberia permitir, dio {permite}"
    assert niega == "Deny", f"la instancia de Seguros deberia negar, dio {niega}"


def test_recursos_accesibles_filtra_por_servicio_y_cuenta():
    """La consulta barre solo los recursos del servicio de la accion y cuenta los Allow."""
    recs = cargar_recursos()
    filas = recursos_mod.accesibles(CUENTA, recs, "mlopez", "ec2:StartInstances")
    assert all(arn.startswith("arn:aws:ec2:") for _, arn, _, _ in filas)
    allow = [arn for d, arn, _, _ in filas if d == "Allow"]
    assert len(allow) == 2, f"mlopez deberia alcanzar 2 instancias de Creditos, alcanzo {len(allow)}"
    assert all("credito" in arn for arn in allow)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def recolectar():
    """Devuelve las funciones test_* del modulo."""
    modulo = sys.modules[__name__]
    return [(n, getattr(modulo, n)) for n in dir(modulo) if n.startswith("test_")]


def main():
    """Corre la suite y devuelve la cantidad de fallos como exit code."""
    tests = recolectar()
    print(f"Corriendo {len(tests)} tests\n" + "-" * 70)

    fallos = []
    for nombre, funcion in tests:
        try:
            funcion()
            print(f"  [OK] {nombre}")
        except AssertionError as e:
            print(f"  [XX] {nombre}\n       {e}")
            fallos.append(nombre)
        except Exception:
            print(f"  [!!] {nombre}  (se rompio, no fallo)")
            traceback.print_exc()
            fallos.append(nombre)

    print("-" * 70)
    if fallos:
        print(f"{len(fallos)} de {len(tests)} tests fallaron: {', '.join(fallos)}")
    else:
        print(f"Los {len(tests)} tests pasaron.")
    return len(fallos)


if __name__ == "__main__":
    sys.exit(main())
