# New-dataset model — taxonomy=4class, split=group

- packets: 910745
- classes: [np.str_('benign'), np.str_('hydra_bruteforce'), np.str_('nmap_scan'), np.str_('stress_test')]
- class counts: {np.str_('benign'): 829915, np.str_('hydra_bruteforce'): 36469, np.str_('nmap_scan'): 1680, np.str_('stress_test'): 42681}

- split: group  (train 733621 / test 177124)

==================================================================
  Random Forest
==================================================================
                  precision    recall  f1-score   support

          benign     0.9963    0.9984    0.9973    162922
hydra_bruteforce     0.9631    0.9394    0.9511      7442
       nmap_scan     0.9937    0.8681    0.9267       364
     stress_test     0.9990    0.9814    0.9901      6396

        accuracy                         0.9950    177124
       macro avg     0.9880    0.9468    0.9663    177124
    weighted avg     0.9950    0.9950    0.9950    177124

  overall accuracy   : 0.9950
  balanced accuracy  : 0.9468   (macro-avg recall)
  macro F1 (test)    : 0.9663
  macro F1 (train)   : 1.0000   [train-test gap = +0.0337]

  Confusion matrix (rows=true, cols=pred):
         benign  hydra_brut   nmap_scan  stress_tes
    benign             162654         260           2           6
    hydra_brutefor        451        6991           0           0
    nmap_scan              42           6         316           0
    stress_test           117           2           0        6277

==================================================================
  Hist Gradient Boosting
==================================================================
                  precision    recall  f1-score   support

          benign     0.9976    0.9954    0.9965    162922
hydra_bruteforce     0.9151    0.9608    0.9374      7442
       nmap_scan     0.9418    0.9780    0.9596       364
     stress_test     0.9884    0.9851    0.9868      6396

        accuracy                         0.9936    177124
       macro avg     0.9607    0.9798    0.9701    177124
    weighted avg     0.9937    0.9936    0.9936    177124

  overall accuracy   : 0.9936
  balanced accuracy  : 0.9798   (macro-avg recall)
  macro F1 (test)    : 0.9701
  macro F1 (train)   : 0.9931   [train-test gap = +0.0230]

  Confusion matrix (rows=true, cols=pred):
         benign  hydra_brut   nmap_scan  stress_tes
    benign             162175         652          22          73
    hydra_brutefor        291        7150           0           1
    nmap_scan               5           3         356           0
    stress_test            87           8           0        6301

**Best: Hist Gradient Boosting — macro-F1=0.9701, balanced-acc=0.9798, acc=0.9936**
Artifact: `models/multiclass/hgb_newdataset_4class.joblib`