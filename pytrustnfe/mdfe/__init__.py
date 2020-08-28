# -*- coding: utf-8 -*-
# © 2016 Danimar Ribeiro, Trustcode
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).
import hashlib
import os
import re
import requests
from lxml import etree
from .patch import has_patch
from .assinatura import Assinatura
from pytrustnfe.xml import render_xml, sanitize_response
from pytrustnfe.utils import gerar_chave, ChaveNFe
from pytrustnfe.Servidores import localizar_url
from pytrustnfe.urls import url_qrcode, url_qrcode_exibicao
from pytrustnfe.certificado import extract_cert_and_key_from_pfx, save_cert_key
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# Zeep
from requests import Session
from zeep import Client
from zeep.transports import Transport


def _generate_mdfe_id(**kwargs):  
    
    for item in kwargs["MDFes"]:
        vals = {
            "cnpj": item["infMDFe"]["emit"]["cnpj_cpf"],
            "estado": item["infMDFe"]["ide"]["cUF"],
            "emissao": "%s%s"
            % (
                item["infMDFe"]["ide"]["dhEmi"][2:4],
                item["infMDFe"]["ide"]["dhEmi"][5:7],
            ),
            "modelo": item["infMDFe"]["ide"]["mod"],
            "serie": item["infMDFe"]["ide"]["serie"],
            "numero": item["infMDFe"]["ide"]["nMDF"],
            "tipo": item["infMDFe"]["ide"]["tpEmis"],
            "codigo": item["infMDFe"]["ide"]["cMDF"],
        }
        chave_mdfe = ChaveNFe(**vals)
        chave_mdfe = gerar_chave(chave_mdfe, "MDFe")
        item["infMDFe"]["Id"] = chave_mdfe
        item["infMDFe"]["ide"]["cDV"] = chave_mdfe[len(chave_mdfe) - 1 :]

        
def _render(certificado, method, sign, **kwargs):

    path = os.path.join(os.path.dirname(__file__), "templates")
    xmlElem_send = render_xml(path, "%s.xml" % method, True, **kwargs)
    #import pudb;pu.db
    #etree.parse('/home/publico/mdfe.xml')
    
    # GRAVA O XML
    mydata = etree.tostring(xmlElem_send)
    myfile = open("/home/publico/mdfe.xml", "w")
    myfile.write(mydata.decode("utf-8"))
    myfile.close()
    
    #print(xmlElem_send)
    
    #xml_element = etree.fromstring(xmlElem_send)
    xml_element = etree.fromstring(mydata)
    modelo = xmlElem_send.find(".//{http://www.portalfiscal.inf.br/mdfe}mod")
    modelo = modelo if modelo is not None else "58"

    if sign:
        signer = Assinatura(certificado.pfx, certificado.password)
        if method == "NfeInutilizacao":
            xml_send = signer.assina_xml(xmlElem_send, kwargs["obj"]["id"])
        if method == "MDFeAutorizacao":
            xml_send = signer.assina_xml(
                xmlElem_send, kwargs["MDFes"][0]["infMDFe"]["Id"]
            )
        elif method == "RecepcaoEvento":
            xml_send = signer.assina_xml(xmlElem_send, kwargs["eventos"][0]["Id"])
        elif method == "RecepcaoEventoManifesto":
            xml_send = signer.assina_xml(
                xmlElem_send, kwargs["manifesto"]["identificador"]
            )

    else:
        xml_send = etree.tostring(xmlElem_send, encoding=str)
    return xml_send

def gerar_qrcode(id_csc: int, csc: str, xml_send: str, cert = False) -> str:
    xml = etree.fromstring(xml_send)
    signature = xml.find(
        ".//{http://www.w3.org/2000/09/xmldsig#}Signature")
    id = xml.find(
        ".//{http://www.portalfiscal.inf.br/mdfe}infMDFe").get('Id')
    if id is None:
        raise Exception("XML Invalido - Sem o ID")

    chave = id.replace('MDFe', '')
    emit_uf = chave[:2]

    tp_amb = xml.find(".//{http://www.portalfiscal.inf.br/mdfe}tpAmb")
    if tp_amb is None:
        raise Exception("XML Invalido - Sem o tipo de ambiente")

    dh_emi = xml.find(".//{http://www.portalfiscal.inf.br/mdfe}dhEmi")
    if dh_emi is None:
        raise Exception("XML Invalido - Sem data de Emissao")
    dh_emi = dh_emi.text.split("-")[2].split("T")[0]

    tp_emis = xml.find(".//{http://www.portalfiscal.inf.br/mdfe}tpEmis")
    if tp_emis is None:
        raise Exception("XML Invalido - Sem tipo de emissao")

    v_nf = xml.find(".//{http://www.portalfiscal.inf.br/mdfe}vNF")
    if v_nf is None:
        raise Exception("XML Invalido - Sem o valor da MDFe")

    url_qrcode_str = url_qrcode(
        estado=emit_uf,
        ambiente=tp_amb.text)
    url_qrcode_exibicao_str = url_qrcode_exibicao(
        estado=emit_uf,
        ambiente=tp_amb.text)

    if tp_emis != 1:
        if signature is None:
            if cert is not False:
                signer = Assinatura(certificado.pfx, certificado.password)
                xml_send = signer.assina_xml(xmlElem_send, id)
            else:
                raise Exception("XML Invalido - Sem assinatura e não "
                                "foi enviado o certificado nos parametros")
        digest_value = xml.find(
            ".//{http://www.w3.org/2000/09/xmldsig#}DigestValue")
        c_hash_qr_code = \
            "{ch_acesso}|{versao}|{tp_amb}|{dh_emi}|" \
            "{v_nf}|{dig_val}|{id_csc}|{csc}".format(
                ch_acesso=chave,
                versao=2,
                tp_amb=tp_amb.text,
                dh_emi=dh_emi,
                v_nf=float(v_nf.text),
                dig_val=digest_value.text,
                id_csc=int(id_csc),
                csc=csc
            )
        c_hash_qr_code = hashlib.sha1(c_hash_qr_code.encode()). \
            hexdigest()
        qr_code_url = 'p={ch_acesso}|{versao}|{tp_amb}|{dh_emi}|" \
                                "{v_nf}|{dig_val}|{id_csc}|{hash}'.format(
            ch_acesso=chave,
            versao=2,
            tp_amb=tp_amb.text,
            dh_emi=dh_emi,
            v_nf=float(v_nf.text),
            dig_val=digest_value.text,
            id_csc=int(id_csc),
            hash=c_hash_qr_code
        )
        qrcode = url_qrcode_str + qr_code_url
        url_consulta = url_qrcode_exibicao_str

        qrCode = xml.find(
            './/{http://www.portalfiscal.inf.br/mdfe}qrCode').text = \
            qrcode
        urlChave = xml.find(
            './/{http://www.portalfiscal.inf.br/mdfe}urlChave').text = \
            url_consulta
    else:
        c_hash_qr_code = \
        "{ch_acesso}|{versao}|{tp_amb}|{id_csc}|{csc}".format(
            ch_acesso=chave,
            versao=2,
            tp_amb=tp_amb.text,
            id_csc=int(id_csc),
            csc=csc
        )
        c_hash_qr_code = hashlib.sha1(c_hash_qr_code.encode()).hexdigest()

        qr_code_url = "p={ch_acesso}|{versao}|{tp_amb}|{id_csc}|" \
                      "{hash}".\
            format(
                ch_acesso=chave,
                versao=2,
                tp_amb=tp_amb.text,
                id_csc=int(id_csc),
                hash=c_hash_qr_code
            )
        qrcode = url_qrcode_str + qr_code_url
        url_consulta = url_qrcode_exibicao_str
        qrCode = xml.find(
            './/{http://www.portalfiscal.inf.br/mdfe}qrCode').text = \
            qrcode
        urlChave = xml.find(
            './/{http://www.portalfiscal.inf.br/mdfe}urlChave').text = \
            url_consulta
    return etree.tostring(xml)

def _get_session(certificado):
    cert, key = extract_cert_and_key_from_pfx(certificado.pfx, certificado.password)
    cert, key = save_cert_key(cert, key)

    session = Session()
    session.cert = (cert, key)
    session.verify = False
    return session


def _get_client(base_url, transport):
    client = Client(base_url, transport=transport)
    port = next(iter(client.wsdl.port_types))
    first_operation = [
        x
        for x in iter(client.wsdl.port_types[port].operations)
        if "zip" not in x.lower()
    ][0]
    return first_operation, client


def _send(certificado, method, **kwargs):
    xml_send = kwargs["xml"]
    base_url = localizar_url(
        method, kwargs["estado"], kwargs["modelo"], kwargs["ambiente"]
    )
    session = _get_session(certificado)
    patch = has_patch(kwargs["estado"], method)
    if patch:
        return patch(session, xml_send, kwargs["ambiente"])
    transport = Transport(session=session)
    first_op, client = _get_client(base_url, transport)
    return _send_zeep(first_op, client, xml_send)


def _send_zeep(first_operation, client, xml_send):
    parser = etree.XMLParser(strip_cdata=False)
    xml = etree.fromstring(xml_send, parser=parser)

    namespaceMDFe = xml.find(".//{http://www.portalfiscal.inf.br/mdfe}MDFe")
    if namespaceMDFe is not None:
        namespaceMDFe.set("xmlns", "http://www.portalfiscal.inf.br/mdfe")

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    with client.settings(raw_response=True):
        response = client.service[first_operation](xml)
        response, obj = sanitize_response(response.text)
        return {
            "sent_xml": xml_send,
            "received_xml": response,
            "object": obj.Body.getchildren()[0],
        }


def xml_autorizar_mdfe(certificado, **kwargs):
    _generate_mdfe_id(**kwargs)
    return _render(certificado, "MDFeAutorizacao", True, **kwargs)


def autorizar_mdfe(certificado, **kwargs):  # Assinar
    if "xml" not in kwargs:
        kwargs["xml"] = xml_autorizar_mdfe(certificado, **kwargs)
    return _send(certificado, "NfeAutorizacao", **kwargs)


def xml_retorno_autorizar_mdfe(certificado, **kwargs):
    return _render(certificado, "NfeRetAutorizacao", False, **kwargs)


def retorno_autorizar_mdfe(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs["xml"] = xml_retorno_autorizar_mdfe(certificado, **kwargs)
    return _send(certificado, "NfeRetAutorizacao", **kwargs)


def xml_recepcao_evento_cancelamento(certificado, **kwargs):  # Assinar
    return _render(certificado, "RecepcaoEvento", True, **kwargs)


def recepcao_evento_cancelamento(certificado, **kwargs):  # Assinar
    if "xml" not in kwargs:
        kwargs["xml"] = xml_recepcao_evento_cancelamento(certificado, **kwargs)
    return _send(certificado, "RecepcaoEvento", **kwargs)


def xml_inutilizar_mdfe(certificado, **kwargs):
    return _render(certificado, "NfeInutilizacao", True, **kwargs)


def inutilizar_mdfe(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs["xml"] = xml_inutilizar_mdfe(certificado, **kwargs)
    return _send(certificado, "NfeInutilizacao", **kwargs)


def xml_consultar_protocolo_mdfe(certificado, **kwargs):
    return _render(certificado, "NfeConsultaProtocolo", False, **kwargs)


def consultar_protocolo_mdfe(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs["xml"] = xml_consultar_protocolo_mdfe(certificado, **kwargs)
    return _send(certificado, "NfeConsultaProtocolo", **kwargs)


def xml_mdfe_status_servico(certificado, **kwargs):
    return _render(certificado, "NfeStatusServico", False, **kwargs)


def mdfe_status_servico(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs["xml"] = xml_mdfe_status_servico(certificado, **kwargs)
    return _send(certificado, "NfeStatusServico", **kwargs)


def xml_consulta_cadastro(certificado, **kwargs):
    return _render(certificado, "NfeConsultaCadastro", False, **kwargs)


def consulta_cadastro(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs["xml"] = xml_consulta_cadastro(certificado, **kwargs)
        kwargs["modelo"] = "55"
    return _send(certificado, "NfeConsultaCadastro", **kwargs)


def xml_recepcao_evento_carta_correcao(certificado, **kwargs):  # Assinar
    return _render(certificado, "RecepcaoEvento", True, **kwargs)


def recepcao_evento_carta_correcao(certificado, **kwargs):  # Assinar
    if "xml" not in kwargs:
        kwargs["xml"] = xml_recepcao_evento_carta_correcao(certificado, **kwargs)
    return _send(certificado, "RecepcaoEvento", **kwargs)


def xml_recepcao_evento_manifesto(certificado, **kwargs):  # Assinar
    return _render(certificado, "RecepcaoEvento", True, **kwargs)


def recepcao_evento_manifesto(certificado, **kwargs):  # Assinar
    if "xml" not in kwargs:
        kwargs["xml"] = xml_recepcao_evento_manifesto(certificado, **kwargs)
    return _send(certificado, "RecepcaoEvento", **kwargs)


def xml_consulta_distribuicao_mdfe(certificado, **kwargs):  # Assinar
    return _render(certificado, "MDFeDistribuicaoDFe", False, **kwargs)


def consulta_distribuicao_mdfe(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs["xml"] = xml_consulta_distribuicao_mdfe(certificado, **kwargs)
    return _send_v310(certificado, **kwargs)


def xml_download_mdfe(certificado, **kwargs):  # Assinar
    return _render(certificado, "MDFeDistribuicaoDFe", False, **kwargs)


def download_mdfe(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs["xml"] = xml_download_mdfe(certificado, **kwargs)
    return _send_v310(certificado, **kwargs)


def _send_v310(certificado, **kwargs):
    xml_send = kwargs["xml"]
    base_url = localizar_url(
        "MDFeDistribuicaoDFe", kwargs["estado"], kwargs["modelo"], kwargs["ambiente"]
    )

    cert, key = extract_cert_and_key_from_pfx(certificado.pfx, certificado.password)
    cert, key = save_cert_key(cert, key)

    session = Session()
    session.cert = (cert, key)
    session.verify = False
    transport = Transport(session=session)

    xml = etree.fromstring(xml_send)
    xml_um = etree.fromstring(
        '<mdfeCabecMsg xmlns="http://www.portalfiscal.inf.br/mdfe/wsdl/"><cUF>AN</cUF><versaoDados>1.00</versaoDados></mdfeCabecMsg>'
    )
    client = Client(base_url, transport=transport)

    port = next(iter(client.wsdl.port_types))
    first_operation = next(iter(client.wsdl.port_types[port].operations))
    with client.settings(raw_response=True):
        response = client.service[first_operation](
            mdfeDadosMsg=xml, _soapheaders=[xml_um]
        )
        response, obj = sanitize_response(response.text)
        return {
            "sent_xml": xml_send,
            "received_xml": response,
            "object": obj.Body.mdfeDistDFeInteresseResponse.mdfeDistDFeInteresseResult,
        }
